//! VMess server: AEAD request header (v2fly wire format) and AEAD body.
//!
//! Inverts [`crate::proto::vmess::VmessStream`]: the server decrypts the
//! AES-ECB auth id (CRC + timestamp window), the sealed header length and
//! the sealed instruction header, verifies the FNV checksum, recovers the
//! port-first target, then answers with the SHA-256-derived response
//! header carrying the client's response byte back.
//!
//! Only the AEAD header and AEAD body securities are served
//! (`aes-128-gcm`, `chacha20-poly1305`); security `none` and the legacy
//! MD5 header (alter-id) are rejected.
//!
//! With the UDP command (cmd 2) the connection stays AEAD-framed but the
//! body chunks become datagrams: each chunk is
//! `port-first addr || payload`, exactly the shape the engine client
//! writes and reads ([`crate::outbound::UdpChannel::Vmess`]); mihomo's
//! vmess serializes the address the same way (port first — metacubex
//! `AddressSerializer`) but pins a fixed destination per connection.
//! Chunk boundaries carry the framing, so one datagram is always exactly
//! one body chunk in both directions.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use aes::cipher::{BlockDecrypt, KeyInit};
use bytes::{Buf, BytesMut};
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::{decode_port_first_addr, encode_port_first_addr, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, now_secs, read_exact_vec, serve_with, ServerConfig, ServerProtocol,
};
use crate::inbound::SharedRelay;
use crate::proto::aead::{Aead, AeadKind};
use crate::proto::fnv1a::fnv1a32;
use crate::proto::vmess::{cmd_key, vmess_kdf, VmessSecurity};
use crate::stream::BoxProxyStream;

/// Protocol version byte (always 1).
const VERSION: u8 = 1;
/// Request options: we serve the standard chunked stream only.
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_AUTH_LEN: u8 = 0x10;
/// Commands.
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
/// Security values on the wire.
const SEC_AES128_GCM: u8 = 0x03;
const SEC_CHACHA20_POLY1305: u8 = 0x04;
const SEC_NONE: u8 = 0x05;
/// AEAD tag length.
const TAG: usize = 16;
/// Largest plaintext chunk sealed per frame (mirrors the client's 8 KiB).
const MAX_CHUNK: usize = 8 * 1024;
/// Auth-id timestamp window in seconds (v2fly rejects beyond ±120 s).
const AUTH_ID_WINDOW: i64 = 120;

/// v2fly KDF path constants (private in `proto::vmess`).
const KDF_AUTH_ID_ENC_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const KDF_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_RESP_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_RESP_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

/// A VMess server: the command key derived from the user uuid and the
/// security policy (`None` = accept the client's `auto` choice).
#[derive(Clone)]
pub struct VmessServer {
    cmd_key: [u8; 16],
    required_security: Option<u8>,
}

impl VmessServer {
    /// Validate the uuid/security once, before binding.
    pub fn new(uuid: &str, security: &str) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid.trim())
            .map_err(|e| Error::config(format!("vmess uuid {uuid:?}: {e}")))?;
        let required_security = match security.trim() {
            "auto" => None,
            other => {
                let wire = match VmessSecurity::parse(other)? {
                    VmessSecurity::Aes128Gcm => SEC_AES128_GCM,
                    VmessSecurity::Chacha20Poly1305 => SEC_CHACHA20_POLY1305,
                    VmessSecurity::None => {
                        return Err(Error::config(
                            "vmess server is AEAD-only: security \"none\" is not supported",
                        ));
                    }
                };
                Some(wire)
            }
        };
        Ok(VmessServer {
            cmd_key: cmd_key(uuid),
            required_security,
        })
    }

    /// Run the server handshake on an accepted connection and hand the
    /// framed stream to the relay.
    pub async fn handle(
        &self,
        mut stream: BoxProxyStream,
        peer: SocketAddr,
        port: u16,
        tag: &str,
        relay: SharedRelay,
    ) -> Result<()> {
        // Fixed prefix: auth id(16) | sealed length(18) | nonce(8).
        let head = read_exact_vec(&mut stream, 42).await?;
        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(&head[..16]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&head[34..42]);
        verify_auth_id(&self.cmd_key, &auth_id)?;

        let len_aead = Aead::new(
            AeadKind::Aes128Gcm,
            &kdf16(&self.cmd_key, &[KDF_HEADER_LEN_KEY, &auth_id, &nonce]),
        )?;
        let len_nonce = kdf12(&self.cmd_key, &[KDF_HEADER_LEN_NONCE, &auth_id, &nonce]);
        let lp = len_aead
            .open(&len_nonce, &auth_id, &head[16..34])
            .map_err(|e| Error::protocol(format!("vmess header length: {e}")))?;
        let hlen = u16::from_be_bytes([lp[0], lp[1]]) as usize;

        let ct = read_exact_vec(&mut stream, hlen + TAG).await?;
        let hdr_aead = Aead::new(
            AeadKind::Aes128Gcm,
            &kdf16(
                &self.cmd_key,
                &[KDF_HEADER_PAYLOAD_KEY, &auth_id, &nonce],
            ),
        )?;
        let hdr_nonce = kdf12(
            &self.cmd_key,
            &[KDF_HEADER_PAYLOAD_NONCE, &auth_id, &nonce],
        );
        let hdr = hdr_aead
            .open(&hdr_nonce, &auth_id, &ct)
            .map_err(|e| Error::protocol(format!("vmess header: {e}")))?;

        // Instruction: V(1) req-iv(16) req-key(16) resp-V(1) opt(1)
        // pad-len|security(1) reserved(1) cmd(1) then the port-first
        // address, padding and the FNV tail.
        if hdr.len() < 42 {
            return Err(Error::protocol("vmess: request header too short"));
        }
        if hdr[0] != VERSION {
            return Err(Error::protocol(format!(
                "vmess: unsupported version {:#x}",
                hdr[0]
            )));
        }
        let mut req_iv = [0u8; 16];
        req_iv.copy_from_slice(&hdr[1..17]);
        let mut req_key = [0u8; 16];
        req_key.copy_from_slice(&hdr[17..33]);
        let response_v = hdr[33];
        let opt = hdr[34];
        let security = hdr[35] & 0x0f;
        let pad_len = (hdr[35] >> 4) as usize;
        let cmd = hdr[37];

        let (body, checksum) = hdr.split_at(hdr.len() - 4);
        let expected = u32::from_be_bytes(checksum.try_into().expect("4 bytes"));
        if fnv1a32(body) != expected {
            return Err(Error::protocol("vmess: header checksum mismatch"));
        }
        if opt & OPT_CHUNK_STREAM == 0 {
            return Err(Error::protocol(
                "vmess: unchunked streams are not supported",
            ));
        }
        if opt & (OPT_CHUNK_MASKING | OPT_AUTH_LEN) != 0 {
            return Err(Error::protocol(
                "vmess: chunk masking / authenticated length are not supported",
            ));
        }
        match security {
            SEC_AES128_GCM | SEC_CHACHA20_POLY1305 => {}
            SEC_NONE => {
                return Err(Error::protocol(
                    "vmess: security none is not supported (AEAD only)",
                ));
            }
            other => {
                return Err(Error::protocol(format!(
                    "vmess: unsupported security {other:#x} (legacy header?)"
                )));
            }
        }
        if let Some(required) = self.required_security {
            if required != security {
                return Err(Error::protocol(format!(
                    "vmess: client requested security {security:#x}, server requires {required:#x}"
                )));
            }
        }

        let (target, used) = decode_port_first_addr(&hdr[38..])?;
        if 38 + used + pad_len > body.len() {
            return Err(Error::protocol("vmess: header padding overruns header"));
        }

        match cmd {
            CMD_TCP | CMD_UDP => {}
            other => return Err(Error::protocol(format!("vmess: bad command {other:#x}"))),
        }

        // Response direction keys: SHA-256 of the request key/IV (v2fly
        // convention), then the AEAD header KDF chain over those.
        let mut resp_key = [0u8; 16];
        resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
        let mut resp_iv = [0u8; 16];
        resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);
        let enc = VmessBody::new(security, resp_key, resp_iv)?;
        let dec = VmessBody::new(security, req_key, req_iv)?;

        // Response header: sealed length, then the sealed
        // [response-V, no option, no command, no command payload]. The
        // client checks the first byte against its random response-V.
        let mut wire = Vec::with_capacity(64);
        let len_aead = Aead::new(
            AeadKind::Aes128Gcm,
            &kdf16(&resp_key, &[KDF_RESP_LEN_KEY]),
        )?;
        let len_nonce = kdf12(&resp_iv, &[KDF_RESP_LEN_IV]);
        let resp_hdr = [response_v, 0u8, 0u8, 0u8];
        len_aead.seal(
            &len_nonce,
            &[],
            &(resp_hdr.len() as u16).to_be_bytes(),
            &mut wire,
        )?;
        let payload_aead = Aead::new(
            AeadKind::Aes128Gcm,
            &kdf16(&resp_key, &[KDF_RESP_PAYLOAD_KEY]),
        )?;
        let payload_nonce = kdf12(&resp_iv, &[KDF_RESP_PAYLOAD_IV]);
        payload_aead.seal(&payload_nonce, &[], &resp_hdr, &mut wire)?;
        stream.write_all(&wire).await?;

        if cmd == CMD_UDP {
            spawn_vmess_udp(stream, peer, tag.to_string(), relay, enc, dec);
            return Ok(());
        }

        let framed = VmessServerStream {
            inner: stream,
            enc,
            dec,
            rbuf: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::new(),
            wbuf: BytesMut::new(),
            pending_plain: 0,
            state: ReadState::Len,
        };
        hand_off(tag, "vmess", port, peer, target, Box::new(framed), relay);
        Ok(())
    }
}

/// Bridge a VMess UDP association to
/// [`crate::inbound::RelayHandler::handle_udp`]: one AEAD body chunk per
/// datagram, `port-first addr || payload` in both directions.
///
/// The chunking is done here rather than through [`VmessServerStream`] so a
/// datagram is never split at the stream's 8 KiB write cap — the client's
/// `read_packet` treats a chunk boundary as a packet boundary.
fn spawn_vmess_udp(
    stream: BoxProxyStream,
    source: SocketAddr,
    tag: String,
    relay: SharedRelay,
    enc: VmessBody,
    dec: VmessBody,
) {
    let (up_tx, up_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    relay.handle_udp(source, tag, up_rx, down_tx);

    let (mut reader, mut writer) = tokio::io::split(stream);
    // Uplink: body chunks off the wire, into the relay.
    tokio::spawn(async move {
        let mut dec = dec;
        loop {
            match read_body_datagram(&mut reader, &mut dec).await {
                Ok(Some(packet)) => {
                    let Ok((target, used)) = decode_port_first_addr(&packet) else {
                        tracing::debug!(target: "engine", "vmess udp {source}: bad datagram address");
                        continue;
                    };
                    if up_tx
                        .send((target, packet[used..].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                // Clean EOF: the client closed the association.
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(target: "engine", "vmess udp {source}: {e}");
                    break;
                }
            }
        }
    });
    // Downlink: one sealed body chunk per relay reply.
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut enc = enc;
        while let Some((target, data)) = down_rx.recv().await {
            let mut frame = Vec::with_capacity(data.len() + 32);
            encode_port_first_addr(&mut frame, &target.host, target.port);
            frame.extend_from_slice(&data);
            let mut out = Vec::with_capacity(frame.len() + TAG + 2);
            if enc.seal_chunk(&frame, &mut out).is_err() {
                continue; // oversize datagram: drop, mirroring a lossy link
            }
            if writer.write_all(&out).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });
}

/// Read one AEAD body chunk as one datagram; `Ok(None)` at EOF. The
/// zero-length chunk (end-of-stream marker) is skipped.
async fn read_body_datagram<R>(reader: &mut R, dec: &mut VmessBody) -> Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    loop {
        let mut len = [0u8; 2];
        match reader.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let n = u16::from_be_bytes(len) as usize;
        if n == 0 {
            continue;
        }
        if n < TAG {
            return Err(Error::protocol("vmess udp: body chunk shorter than a tag"));
        }
        let mut ct = vec![0u8; n];
        reader.read_exact(&mut ct).await?;
        let plain = dec
            .aead
            .open(&dec.nonce.advance(), &[], &ct)
            .map_err(|e| Error::protocol(format!("vmess udp body: {e}")))?;
        return Ok(Some(plain));
    }
}

/// Serve a VMess listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Vmess { uuid, security } = &cfg.protocol else {
        return Err(Error::config("vmess::serve called with a non-vmess protocol"));
    };
    let server = VmessServer::new(uuid, security)?;
    let tag = cfg.tag.clone();
    serve_with(cfg, move |stream, peer, port| {
        let server = server.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        async move { server.handle(stream, peer, port, &tag, relay).await }
    })
    .await
}

/// Verify the AES-ECB auth id: CRC over the first 12 bytes, then the
/// timestamp replay window. A legacy (non-AEAD) request fails here.
fn verify_auth_id(cmd_key: &[u8; 16], auth_id: &[u8; 16]) -> Result<()> {
    let key = &vmess_kdf(cmd_key, &[KDF_AUTH_ID_ENC_KEY])[..16];
    let cipher = aes::Aes128::new_from_slice(key)
        .map_err(|e| Error::crypto(format!("vmess auth id cipher: {e}")))?;
    let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(auth_id);
    cipher.decrypt_block(&mut block);
    let plain: [u8; 16] = block.into();
    let crc = u32::from_be_bytes(plain[12..16].try_into().expect("4 bytes"));
    if crc32fast::hash(&plain[..12]) != crc {
        return Err(Error::protocol(
            "vmess: auth id check failed (unknown uuid, legacy header or wrong key)",
        ));
    }
    let ts = i64::from_be_bytes(plain[..8].try_into().expect("8 bytes"));
    let drift = (now_secs() as i64 - ts).abs();
    if drift > AUTH_ID_WINDOW {
        return Err(Error::protocol(format!(
            "vmess: auth id timestamp drift {drift}s exceeds replay window"
        )));
    }
    Ok(())
}

/// First 16 bytes of a KDF path evaluation.
fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&vmess_kdf(key, paths)[..16]);
    out
}

/// First 12 bytes of a KDF path evaluation (AEAD nonce).
fn kdf12(key: &[u8], paths: &[&[u8]]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&vmess_kdf(key, paths)[..12]);
    out
}

/// Count-based chunk nonce: `be_u16(count) || iv[2..12]` (mirrors
/// `proto::vmess::ChunkNonce`).
struct VmessNonce {
    base_iv: [u8; 16],
    count: u16,
}

impl VmessNonce {
    fn new(iv: [u8; 16]) -> Self {
        VmessNonce {
            base_iv: iv,
            count: 0,
        }
    }

    fn advance(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..].copy_from_slice(&self.base_iv[2..12]);
        self.count = self.count.wrapping_add(1);
        n
    }
}

/// Body cipher for one direction: 2-byte ciphertext length then one AEAD
/// block (the length counts the tag; mirrors `proto::vmess::BodyCodec`).
struct VmessBody {
    aead: Aead,
    nonce: VmessNonce,
}

impl VmessBody {
    fn new(security: u8, key: [u8; 16], iv: [u8; 16]) -> Result<Self> {
        let kind = match security {
            SEC_AES128_GCM => AeadKind::Aes128Gcm,
            SEC_CHACHA20_POLY1305 => AeadKind::Chacha20Poly1305,
            other => {
                return Err(Error::protocol(format!(
                    "vmess: unsupported security {other:#x}"
                )));
            }
        };
        let key = if kind == AeadKind::Aes128Gcm {
            key.to_vec()
        } else {
            // v2fly: chacha key = MD5(key) || MD5(MD5(key))
            let first = Md5::digest(key);
            let second = Md5::digest(first);
            let mut k = Vec::with_capacity(32);
            k.extend_from_slice(&first);
            k.extend_from_slice(&second);
            k
        };
        Ok(VmessBody {
            aead: Aead::new(kind, &key)?,
            nonce: VmessNonce::new(iv),
        })
    }

    fn seal_chunk(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let frame_len = plain
            .len()
            .checked_add(TAG)
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or_else(|| Error::protocol("vmess chunk exceeds 65535 bytes"))?;
        out.extend_from_slice(&(frame_len as u16).to_be_bytes());
        self.aead.seal(&self.nonce.advance(), &[], plain, out)
    }
}

enum ReadState {
    Len,
    Payload(u16),
}

/// The server side of a VMess AEAD session.
struct VmessServerStream {
    inner: BoxProxyStream,
    enc: VmessBody,
    dec: VmessBody,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    pending_plain: usize,
    state: ReadState,
}

impl VmessServerStream {
    fn advance_state(&mut self) -> Result<()> {
        match self.state {
            ReadState::Len => {
                let len = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]);
                self.rbuf.advance(2);
                self.state = ReadState::Payload(len);
            }
            ReadState::Payload(len) => {
                let n = len as usize;
                if n == 0 {
                    self.state = ReadState::Len;
                    return Ok(());
                }
                if n < TAG {
                    return Err(Error::protocol("vmess body chunk shorter than a tag"));
                }
                let pt = self
                    .dec
                    .aead
                    .open(&self.dec.nonce.advance(), &[], &self.rbuf[..n])
                    .map_err(|e| Error::protocol(format!("vmess body: {e}")))?;
                self.rbuf.advance(n);
                self.plain.extend_from_slice(&pt);
                self.state = ReadState::Len;
            }
        }
        Ok(())
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain.is_empty() {
                let n = self.plain.len().min(dst.remaining());
                dst.put_slice(&self.plain[..n]);
                self.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            let need = match &self.state {
                ReadState::Len => 2,
                ReadState::Payload(len) => *len as usize,
            };
            if self.rbuf.len() >= need {
                if let Err(e) = self.advance_state() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                }
                continue;
            }
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                if self.rbuf.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vmess: truncated stream",
                )));
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
    }
}

impl AsyncRead for VmessServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for VmessServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            let take = buf.len().min(MAX_CHUNK);
            let mut out = Vec::with_capacity(take + 2 + TAG);
            this.enc
                .seal_chunk(&buf[..take], &mut out)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            this.wbuf = BytesMut::from(&out[..]);
            this.pending_plain = take;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vmess: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::vmess::VmessOut;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn fresh_uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    async fn spawn_server(uuid: &str, security: &str) -> (Arc<Capture>, SocketAddr) {
        let cfg = ServerConfig {
            tag: "vmess-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Vmess {
                uuid: uuid.into(),
                security: security.into(),
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client(uuid: &str, security: &str, port: u16) -> VmessOut {
        VmessOut {
            server: "127.0.0.1".into(),
            port,
            uuid: uuid::Uuid::parse_str(uuid).unwrap(),
            security: VmessSecurity::parse(security).unwrap(),
        }
    }

    /// Echo one payload through the real client codec.
    async fn roundtrip(
        uuid: &str,
        client_security: &str,
        server_security: &str,
    ) -> (Arc<Capture>, NetAddr) {
        let (capture, addr) = spawn_server(uuid, server_security).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = crate::proto::vmess::VmessStream::handshake(
            Box::new(tcp),
            &client(uuid, client_security, addr.port()),
            &target,
            false,
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"ping");
        (capture, target)
    }

    #[tokio::test]
    async fn aes128_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, target) = roundtrip(&uuid, "auto", "auto").await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn chacha_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, target) = roundtrip(&uuid, "chacha20-poly1305", "auto").await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn pinned_security_matches_client() {
        let uuid = fresh_uuid();
        let (capture, target) = roundtrip(&uuid, "auto", "aes-128-gcm").await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn unknown_uuid_relays_nothing() {
        let (capture, addr) = spawn_server(&fresh_uuid(), "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = crate::proto::vmess::VmessStream::handshake(
            Box::new(tcp),
            &client(&fresh_uuid(), "auto", addr.port()),
            &target,
            false,
        )
        .await
        .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn security_none_is_rejected() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = crate::proto::vmess::VmessStream::handshake(
            Box::new(tcp),
            &client(&uuid, "none", addr.port()),
            &target,
            false,
        )
        .await
        .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn security_mismatch_is_rejected() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "chacha20-poly1305").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // "auto" resolves to aes-128-gcm, which the server must refuse.
        let mut stream = crate::proto::vmess::VmessStream::handshake(
            Box::new(tcp),
            &client(&uuid, "auto", addr.port()),
            &target,
            false,
        )
        .await
        .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[test]
    fn config_validation() {
        assert!(VmessServer::new("not-a-uuid", "auto").is_err());
        assert!(VmessServer::new(fresh_uuid().as_str(), "none").is_err());
        assert!(VmessServer::new(fresh_uuid().as_str(), "aes-256-cfb").is_err());
        assert!(VmessServer::new(fresh_uuid().as_str(), "auto").is_ok());
    }

    /// UDP command (cmd 2) roundtrip through the engine's own client:
    /// `VmessStream` for the handshake, `port-first addr || payload` for
    /// the send, and the client's own `read_packet` for the reply.
    #[tokio::test]
    async fn udp_command_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // Like the outbound, the instruction header carries no real target.
        let placeholder =
            NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut stream = crate::proto::vmess::VmessStream::handshake(
            Box::new(tcp),
            &client(&uuid, "auto", addr.port()),
            &placeholder,
            true,
        )
        .await
        .unwrap();
        let mut frame = Vec::new();
        encode_port_first_addr(&mut frame, &target.host, target.port);
        frame.extend_from_slice(b"ping");
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        let packet = tokio::time::timeout(Duration::from_secs(5), stream.read_packet())
            .await
            .expect("timeout")
            .unwrap();
        let (from, used) = decode_port_first_addr(&packet).unwrap();
        assert_eq!(from, target);
        assert_eq!(&packet[used..], b"ping");
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.relayed(), 0);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "vmess-test");
    }
}