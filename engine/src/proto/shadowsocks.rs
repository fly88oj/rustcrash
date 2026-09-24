//! Shadowsocks outbound: legacy AEAD (SIP004) and 2022 (SIP022) methods,
//! TCP streams and native UDP relay.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::Engine;
use bytes::{Buf, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::{decode_socks_addr, encode_socks_addr, NetAddr};
use crate::error::{Error, Result};
use crate::proto::aead::{evp_bytes_to_key, ss2022_subkey, ss_subkey_legacy, Aead, AeadKind, SsNonce};
use crate::stream::BoxProxyStream;

/// Shadowsocks method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsMethod {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20IetfPoly1305,
    Blake3Aes128Gcm,
    Blake3Aes256Gcm,
}

impl SsMethod {
    /// Parse the method name accepted by mihomo/sing-box configs.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "aes-128-gcm" => Ok(SsMethod::Aes128Gcm),
            "aes-256-gcm" => Ok(SsMethod::Aes256Gcm),
            "chacha20-ietf-poly1305" | "xchacha20-ietf-poly1305" => {
                Ok(SsMethod::Chacha20IetfPoly1305)
            }
            "2022-blake3-aes-128-gcm" => Ok(SsMethod::Blake3Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Ok(SsMethod::Blake3Aes256Gcm),
            other => Err(Error::config(format!(
                "unsupported shadowsocks method {other:?} (supported: aes-128-gcm, \
                 aes-256-gcm, chacha20-ietf-poly1305, 2022-blake3-aes-128-gcm, \
                 2022-blake3-aes-256-gcm)"
            ))),
        }
    }

    fn kind(self) -> AeadKind {
        match self {
            SsMethod::Aes128Gcm | SsMethod::Blake3Aes128Gcm => AeadKind::Aes128Gcm,
            SsMethod::Aes256Gcm | SsMethod::Blake3Aes256Gcm => AeadKind::Aes256Gcm,
            SsMethod::Chacha20IetfPoly1305 => AeadKind::Chacha20Poly1305,
        }
    }

    /// Key length == salt length for every supported method.
    pub fn key_len(self) -> usize {
        self.kind().key_len()
    }

    pub fn is_2022(self) -> bool {
        matches!(self, SsMethod::Blake3Aes128Gcm | SsMethod::Blake3Aes256Gcm)
    }

    /// Derive the fixed main key from the password.
    pub fn derive_key(self, password: &str) -> Result<Vec<u8>> {
        if self.is_2022() {
            // SIP022: the password IS a base64 PSK; no KDF allowed.
            let key = base64::engine::general_purpose::STANDARD
                .decode(password.trim())
                .map_err(|_| {
                    Error::config("shadowsocks 2022 password must be a base64 PSK")
                })?;
            if key.len() != self.key_len() {
                return Err(Error::config(format!(
                    "shadowsocks 2022 PSK must be {} bytes, got {}",
                    self.key_len(),
                    key.len()
                )));
            }
            Ok(key)
        } else {
            Ok(evp_bytes_to_key(password.as_bytes(), self.key_len()))
        }
    }
}

/// Outbound Shadowsocks endpoint.
#[derive(Debug, Clone)]
pub struct SsOut {
    pub server: String,
    pub port: u16,
    pub method: SsMethod,
    pub password: String,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn fresh_salt(len: usize) -> Vec<u8> {
    let mut s = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

fn subkey_for(method: SsMethod, key: &[u8], salt: &[u8]) -> Vec<u8> {
    if method.is_2022() {
        ss2022_subkey(key, salt, method.key_len())
    } else {
        ss_subkey_legacy(key, salt)
    }
}

/// Seal one length+payload chunk and append it to `out`.
fn seal_chunk(aead: &Aead, nonce: &mut SsNonce, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let len = u16::try_from(plain.len())
        .map_err(|_| Error::protocol("shadowsocks chunk exceeds 65535 bytes"))?;
    aead.seal(&nonce.advance(), &[], &len.to_be_bytes(), out)?;
    aead.seal(&nonce.advance(), &[], plain, out)?;
    Ok(())
}

enum ReadState {
    /// Waiting for the response salt (key_len bytes).
    Salt,
    /// Waiting for the 2022 fixed response header (11 + salt + tag).
    Fixed2022,
    /// Waiting for a length chunk (2 + tag).
    Len,
    /// Waiting for a payload chunk of `len` bytes.
    Payload(u16),
}

/// An AEAD-framed Shadowsocks TCP session over an arbitrary transport.
pub struct SsStream {
    inner: BoxProxyStream,
    method: SsMethod,
    derived_key: Vec<u8>,
    sent_salt: Vec<u8>,
    enc: Aead,
    enc_nonce: SsNonce,
    /// Allocated after the response salt arrives.
    dec: Option<Aead>,
    dec_nonce: SsNonce,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    state: ReadState,
}

impl SsStream {
    /// Run the client handshake over an established transport and return
    /// the framed stream. `initial` (when non-empty) rides the header chunk.
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &SsOut,
        target: &NetAddr,
        initial: &[u8],
    ) -> Result<Self> {
        let key = cfg.method.derive_key(&cfg.password)?;
        let salt = fresh_salt(cfg.method.key_len());
        let subkey = subkey_for(cfg.method, &key, &salt);
        let enc = Aead::new(cfg.method.kind(), &subkey)?;
        let dec = Aead::new(cfg.method.kind(), &subkey)?;

        let mut wire = Vec::with_capacity(salt.len() + 64);
        wire.extend_from_slice(&salt);

        let mut enc_nonce = SsNonce::new();
        if cfg.method.is_2022() {
            let mut var = Vec::with_capacity(48);
            encode_socks_addr(&mut var, &target.host, target.port);
            // SIP022: a header chunk must carry payload or padding.
            let pad_len: u16 = if initial.is_empty() { 16 } else { 0 };
            var.extend_from_slice(&pad_len.to_be_bytes());
            var.extend(std::iter::repeat_n(0u8, pad_len as usize));
            var.extend_from_slice(initial);

            let var_len = u16::try_from(var.len())
                .map_err(|_| Error::protocol("ss2022 var header exceeds 65535 bytes"))?;
            let mut fixed = Vec::with_capacity(11);
            fixed.push(0u8); // type: client stream
            fixed.extend_from_slice(&now_secs().to_be_bytes());
            fixed.extend_from_slice(&var_len.to_be_bytes()); // var header length
            enc.seal(&enc_nonce.advance(), &[], &fixed, &mut wire)?;
            enc.seal(&enc_nonce.advance(), &[], &var, &mut wire)?;
        } else {
            let mut hdr = Vec::with_capacity(48);
            encode_socks_addr(&mut hdr, &target.host, target.port);
            hdr.extend_from_slice(initial);
            seal_chunk(&enc, &mut enc_nonce, &hdr, &mut wire)?;
        }

        let mut stream = SsStream {
            inner: transport,
            method: cfg.method,
            derived_key: key,
            sent_salt: salt,
            enc,
            enc_nonce,
            dec: Some(dec),
            dec_nonce: SsNonce::new(),
            rbuf: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::with_capacity(16 * 1024),
            wbuf: BytesMut::new(),
            state: ReadState::Salt,
        };
        stream.inner.write_all(&wire).await?;
        Ok(stream)
    }

    /// Consume one protocol unit from `rbuf`, decrypting into `plain`.
    fn advance_state(&mut self) -> Result<()> {
        const TAG: usize = 16;
        match self.state {
            ReadState::Salt => {
                let salt_len = self.method.key_len();
                let salt = self.rbuf[..salt_len].to_vec();
                self.rbuf.advance(salt_len);
                let subkey = subkey_for(self.method, &self.derived_key, &salt);
                self.dec = Some(Aead::new(self.method.kind(), &subkey)?);
                self.dec_nonce = SsNonce::new();
                self.state = if self.method.is_2022() {
                    ReadState::Fixed2022
                } else {
                    ReadState::Len
                };
            }
            ReadState::Fixed2022 => {
                let salt_len = self.sent_salt.len();
                let n = 11 + salt_len + TAG;
                let dec = self.dec.as_ref().expect("dec built in Salt state");
                let pt = dec
                    .open(&self.dec_nonce.advance(), &[], &self.rbuf[..n])
                    .map_err(|e| Error::protocol(format!("ss2022 response header: {e}")))?;
                self.rbuf.advance(n);
                let frame_type = pt[0];
                if frame_type != 1 {
                    return Err(Error::protocol("ss2022 response: not a server frame"));
                }
                let ts = u64::from_be_bytes(pt[1..9].try_into().unwrap());
                let echoed = &pt[9..9 + salt_len];
                if echoed != self.sent_salt.as_slice() {
                    return Err(Error::protocol("ss2022 response salt mismatch"));
                }
                let drift = now_secs().abs_diff(ts);
                if drift > 60 {
                    return Err(Error::protocol(format!(
                        "ss2022 response timestamp drift {drift}s exceeds replay window"
                    )));
                }
                let len = u16::from_be_bytes(
                    pt[9 + salt_len..11 + salt_len].try_into().unwrap(),
                );
                self.state = ReadState::Payload(len);
            }
            ReadState::Len => {
                let dec = self.dec.as_ref().expect("dec built in Salt state");
                let pt = dec
                    .open(&self.dec_nonce.advance(), &[], &self.rbuf[..2 + TAG])
                    .map_err(|e| Error::protocol(format!("ss length chunk: {e}")))?;
                self.rbuf.advance(2 + TAG);
                let len = u16::from_be_bytes([pt[0], pt[1]]);
                self.state = ReadState::Payload(len);
            }
            ReadState::Payload(len) => {
                let n = len as usize + TAG;
                let dec = self.dec.as_ref().expect("dec built in Salt state");
                let pt = dec
                    .open(&self.dec_nonce.advance(), &[], &self.rbuf[..n])
                    .map_err(|e| Error::protocol(format!("ss payload chunk: {e}")))?;
                self.rbuf.advance(n);
                self.plain.extend_from_slice(&pt);
                self.state = ReadState::Len;
            }
        }
        Ok(())
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.plain.is_empty() {
                let n = self.plain.len().min(dst.remaining());
                dst.put_slice(&self.plain[..n]);
                self.plain.advance(n);
                return Poll::Ready(Ok(()));
            }

            const TAG: usize = 16;
            let need = match &self.state {
                ReadState::Salt => self.method.key_len(),
                ReadState::Fixed2022 => 11 + self.sent_salt.len() + TAG,
                ReadState::Len => 2 + TAG,
                ReadState::Payload(len) => *len as usize + TAG,
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
                    "shadowsocks: truncated stream",
                )));
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            let mut out = Vec::with_capacity(buf.len() + 34);
            seal_chunk(&this.enc, &mut this.enc_nonce, buf, &mut out)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            this.wbuf = BytesMut::from(&out[..]);
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadowsocks: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for SsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

/// A Shadowsocks UDP relay session (one bound local socket; per-packet
/// addressing for both legacy AEAD and 2022).
pub struct SsUdp {
    socket: tokio::net::UdpSocket,
    server: std::net::SocketAddr,
    method: SsMethod,
    key: Vec<u8>,
    /// 2022: client session id + packet counter (server validates replay
    /// on the (session id, packet id) pair).
    session_id: u64,
    packet_id: u64,
    aes_block: Option<AesBlock>,
}

enum AesBlock {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
}

impl AesBlock {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block[..]);
        match self {
            AesBlock::Aes128(c) => c.encrypt_block(b),
            AesBlock::Aes256(c) => c.encrypt_block(b),
        }
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        let b = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block[..]);
        match self {
            AesBlock::Aes128(c) => c.decrypt_block(b),
            AesBlock::Aes256(c) => c.decrypt_block(b),
        }
    }
}

impl SsUdp {
    /// Bind a local UDP socket and point it at the Shadowsocks server.
    pub async fn bind(cfg: &SsOut) -> Result<Self> {
        let key = cfg.method.derive_key(&cfg.password)?;
        let server = resolve_first(&cfg.server, cfg.port).await?;
        let socket = tokio::net::UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        let aes_block = if cfg.method.is_2022() {
            Some(match cfg.method.kind() {
                AeadKind::Aes128Gcm => {
                    AesBlock::Aes128(Box::new(aes::Aes128::new_from_slice(&key).unwrap()))
                }
                _ => AesBlock::Aes256(Box::new(aes::Aes256::new_from_slice(&key).unwrap())),
            })
        } else {
            None
        };
        let mut session_id = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut session_id);
        Ok(SsUdp {
            socket,
            server,
            method: cfg.method,
            key,
            session_id: u64::from_be_bytes(session_id),
            packet_id: 0,
            aes_block,
        })
    }

    /// Send one datagram to `target` through the relay.
    pub async fn send(&mut self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let mut packet = Vec::with_capacity(data.len() + 96);
        if self.method.is_2022() {
            let (wire, plain) = self.separate_header();
            packet.extend_from_slice(&wire);
            let subkey = ss2022_subkey(&self.key, &plain[..8], self.method.key_len());
            let aead = Aead::new(self.method.kind(), &subkey)?;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&plain[4..16]);
            let mut body = Vec::with_capacity(data.len() + 40);
            body.push(0u8); // client frame
            body.extend_from_slice(&now_secs().to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes()); // padding
            encode_socks_addr(&mut body, &target.host, target.port);
            body.extend_from_slice(data);
            aead.seal(&nonce, &[], &body, &mut packet)?;
        } else {
            // AEAD UDP packets are self-delimiting datagrams: salt plus ONE
            // AEAD block over the addressed payload, with an all-zero
            // nonce — no TCP-style length framing.
            let salt = fresh_salt(self.method.key_len());
            packet.extend_from_slice(&salt);
            let subkey = ss_subkey_legacy(&self.key, &salt);
            let aead = Aead::new(self.method.kind(), &subkey)?;
            let mut body = Vec::with_capacity(data.len() + 40);
            encode_socks_addr(&mut body, &target.host, target.port);
            body.extend_from_slice(data);
            aead.seal(&[0u8; 12], &[], &body, &mut packet)?;
        }
        self.socket
            .send_to(&packet, self.server)
            .await
            .map_err(|e| Error::network(format!("ss udp send: {e}")))?;
        Ok(())
    }

    /// Receive one datagram from the relay.
    pub async fn recv(&mut self) -> Result<(NetAddr, Vec<u8>)> {
        const TAG: usize = 16;
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, _) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| Error::network(format!("ss udp recv: {e}")))?;
            let data = &buf[..n];
            let result = if self.method.is_2022() {
                if data.len() < 16 + TAG {
                    continue; // runt packet
                }
                // The response header is AES-ECB encrypted on the wire;
                // subkey and nonce come from the DECRYPTED bytes (server
                // session id = plain[..8]).
                let mut plain = [0u8; 16];
                plain.copy_from_slice(&data[..16]);
                if let Some(cipher) = &self.aes_block {
                    cipher.decrypt_block(&mut plain);
                }
                let subkey = ss2022_subkey(&self.key, &plain[..8], self.method.key_len());
                let aead = match Aead::new(self.method.kind(), &subkey) {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&plain[4..16]);
                let Ok(body) = aead.open(&nonce, &[], &data[16..]) else {
                    continue;
                };
                parse_ss2022_udp_server_frame(&body)
            } else {
                // One AEAD block after the salt; zero nonce (see send).
                if data.len() < self.method.key_len() + TAG {
                    continue;
                }
                let salt = &data[..self.method.key_len()];
                let subkey = ss_subkey_legacy(&self.key, salt);
                let Ok(aead) = Aead::new(self.method.kind(), &subkey) else {
                    continue;
                };
                let Ok(payload) = aead.open(&[0u8; 12], &[], &data[self.method.key_len()..])
                else {
                    continue;
                };
                parse_udp_frame(&payload)
            };
            if let Some(r) = result {
                return Ok(r);
            }
        }
    }

    /// 2022: the 16-byte AES-block-encrypted separate header carrying
    /// session id and packet id.
    /// Build the packet's 16-byte separate header. Returns
    /// `(wire, plain)`: the WIRE bytes are AES-ECB(psk) encrypted, while
    /// the subkey and nonce are derived from the PLAINTEXT header
    /// (sing-shadowsocks `newPacket`: `SessionKey(psk, packetHeader[:8])`
    /// and `packetHeader[4:16]` are read AFTER the in-place decrypt).
    fn separate_header(&mut self) -> ([u8; 16], [u8; 16]) {
        self.packet_id += 1;
        let mut plain = [0u8; 16];
        plain[..8].copy_from_slice(&self.session_id.to_be_bytes());
        plain[8..].copy_from_slice(&self.packet_id.to_be_bytes());
        let mut wire = plain;
        if let Some(cipher) = &self.aes_block {
            cipher.encrypt_block(&mut wire);
        }
        (wire, plain)
    }
}

/// Server→client 2022 UDP frame: type(1) timestamp(8) client-session(8)
/// padding-len(2) padding addr payload.
fn parse_ss2022_udp_server_frame(body: &[u8]) -> Option<(NetAddr, Vec<u8>)> {
    if body.len() < 19 || body[0] != 1 {
        return None;
    }
    let pad_len = u16::from_be_bytes([body[17], body[18]]) as usize;
    let rest = &body[19 + pad_len..];
    parse_udp_frame(rest)
}

/// Legacy/2022-common trailer: socks addr followed by payload.
fn parse_udp_frame(data: &[u8]) -> Option<(NetAddr, Vec<u8>)> {
    let (addr, used) = decode_socks_addr(data).ok()?;
    Some((addr, data[used..].to_vec()))
}

async fn resolve_first(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| Error::network(format!("resolve {host}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::network(format!("no address for {host}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Fresh per-run credential for in-process loopback tests: nothing
    /// usable is ever committed.
    fn fresh_password() -> String {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// In-process legacy-AEAD Shadowsocks "server" that understands just
    /// enough of the protocol to validate the client framing: read salt,
    /// decrypt the address chunk, then reply one chunk.
    async fn legacy_echo_server(listener: TcpListener, key: Vec<u8>) {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let key = key.clone();
            tokio::spawn(async move {
                let mut enc_salt = [0u8; 16];
                sock.read_exact(&mut enc_salt).await.unwrap();
                let skey = ss_subkey_legacy(&key, &enc_salt);
                let dec = Aead::new(AeadKind::Aes128Gcm, &skey).unwrap();
                let mut dnonce = SsNonce::new();
                async fn read_exact(sock: &mut TcpStream, n: usize) -> Vec<u8> {
                    let mut b = vec![0u8; n];
                    sock.read_exact(&mut b).await.unwrap();
                    b
                }
                let hdr_len_ct = read_exact(&mut sock, 2 + 16).await;
                let pt = dec.open(&dnonce.advance(), &[], &hdr_len_ct).unwrap();
                let hlen = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                let hdr_ct = read_exact(&mut sock, hlen + 16).await;
                let hdr = dec.open(&dnonce.advance(), &[], &hdr_ct).unwrap();
                let (target, _) = decode_socks_addr(&hdr).unwrap();
                assert_eq!(target.host, Host::Domain("echo.test".into()));
                assert_eq!(target.port, 443);
                // Server response: own salt + one chunk.
                let mut resp_salt = [0u8; 16];
                rand::rngs::OsRng.fill_bytes(&mut resp_salt);
                let rskey = ss_subkey_legacy(&key, &resp_salt);
                let renc = Aead::new(AeadKind::Aes128Gcm, &rskey).unwrap();
                let mut enonce = SsNonce::new();
                let mut out = resp_salt.to_vec();
                seal_chunk(&renc, &mut enonce, b"pong", &mut out).unwrap();
                sock.write_all(&out).await.unwrap();
                // Read one more client chunk to exercise the reader.
                let len_ct = read_exact(&mut sock, 2 + 16).await;
                let pt = dec.open(&dnonce.advance(), &[], &len_ct).unwrap();
                let len = u16::from_be_bytes([pt[0], pt[1]]) as usize;
                let ct = read_exact(&mut sock, len + 16).await;
                let payload = dec.open(&dnonce.advance(), &[], &ct).unwrap();
                assert_eq!(&payload[..], b"ping");
            });
        }
    }

    #[tokio::test]
    async fn legacy_tcp_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let password = fresh_password();
        let key = SsMethod::Aes128Gcm.derive_key(&password).unwrap();
        tokio::spawn(legacy_echo_server(listener, key));
        let cfg = SsOut {
            server: "127.0.0.1".into(),
            port: addr.port(),
            method: SsMethod::Aes128Gcm,
            password,
        };
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = SsStream::handshake(
            Box::new(tcp),
            &cfg,
            &NetAddr::domain("echo.test", 443).unwrap(),
            b"",
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
        assert_eq!(&buf[..n], b"pong");
    }

    #[tokio::test]
    async fn method_parse_rejects_unknown() {
        assert!(SsMethod::parse("rc4-md5").is_err());
        assert_eq!(SsMethod::parse("aes-256-gcm").unwrap(), SsMethod::Aes256Gcm);
        assert_eq!(
            SsMethod::parse("2022-blake3-aes-256-gcm").unwrap(),
            SsMethod::Blake3Aes256Gcm
        );
    }

    #[test]
    fn psk_validation() {
        let m = SsMethod::Blake3Aes128Gcm;
        let psk = base64::engine::general_purpose::STANDARD.encode([9u8; 16]);
        assert_eq!(m.derive_key(&psk).unwrap(), vec![9u8; 16]);
        assert!(m.derive_key("not-base64!!").is_err());
        let wrong_size = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        assert!(m.derive_key(&wrong_size).is_err());
    }

    #[test]
    fn udp_frame_roundtrip() {
        let mut frame = Vec::new();
        encode_socks_addr(&mut frame, &Host::Domain("srv.example".into()), 53);
        frame.extend_from_slice(b"\x01\x02payload");
        let (addr, data) = parse_udp_frame(&frame).unwrap();
        assert_eq!(addr.host, Host::Domain("srv.example".into()));
        assert_eq!(addr.port, 53);
        assert_eq!(data, b"\x01\x02payload");
    }

    #[test]
    fn ss2022_udp_server_frame_parses() {
        let mut body = vec![1u8];
        body.extend_from_slice(&1234u64.to_be_bytes());
        body.extend_from_slice(&42u64.to_be_bytes()); // client session id
        body.extend_from_slice(&0u16.to_be_bytes()); // padding
        let mut addr = Vec::new();
        encode_socks_addr(&mut addr, &Host::Domain("a.b".into()), 80);
        body.extend_from_slice(&addr);
        body.extend_from_slice(b"xyz");
        let mut bad = body.clone();
        bad[0] = 0;
        assert!(parse_ss2022_udp_server_frame(&bad).is_none());
    }
}
