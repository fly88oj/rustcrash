//! VMess AEAD outbound (v2fly wire format): request header sealed with the
//! AEAD KDF chain, AES-128-GCM / ChaCha20-Poly1305 / none chunked body,
//! and the matching response header decode.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use aes::cipher::{BlockEncrypt, KeyInit};
use bytes::{Buf, BytesMut};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::proto::aead::AeadKind;
use crate::proto::fnv1a::fnv1a32;
use crate::stream::BoxProxyStream;

/// Protocol version byte (always 1).
const VERSION: u8 = 1;

/// VMess request options; we always set the standard chunked stream.
const OPT_CHUNK_STREAM: u8 = 0x01;

/// Security values on the wire.
const SEC_AES128_GCM: u8 = 0x03;
const SEC_CHACHA20_POLY1305: u8 = 0x04;
const SEC_NONE: u8 = 0x05;

/// Commands.
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

/// Fixed salt appended to the UUID bytes when deriving the command key.
const CMDKEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// KDF path constants (v2fly `proxy/vmess/aead/consts.go`).
const KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const KDF_AUTH_ID_ENC_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const KDF_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_HEADER_LEN_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_RESP_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_RESP_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";

/// Body security negotiated for the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmessSecurity {
    Aes128Gcm,
    Chacha20Poly1305,
    None,
}

impl VmessSecurity {
    /// Map a mihomo `cipher` value. `auto` resolves to AES-128-GCM (any
    /// AEAD choice is accepted by the server; determinism aids debugging).
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "auto" | "aes-128-gcm" => Ok(VmessSecurity::Aes128Gcm),
            "chacha20-poly1305" | "zero" => Ok(VmessSecurity::Chacha20Poly1305),
            "none" => Ok(VmessSecurity::None),
            other => Err(Error::config(format!(
                "unsupported vmess security {other:?} (supported: auto, aes-128-gcm, \
                 chacha20-poly1305, none)"
            ))),
        }
    }

    fn wire(self) -> u8 {
        match self {
            VmessSecurity::Aes128Gcm => SEC_AES128_GCM,
            VmessSecurity::Chacha20Poly1305 => SEC_CHACHA20_POLY1305,
            VmessSecurity::None => SEC_NONE,
        }
    }
}

/// Outbound VMess endpoint.
#[derive(Debug, Clone)]
pub struct VmessOut {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub security: VmessSecurity,
}

/// The 16-byte command key: `MD5(uuid_bytes || CMDKEY_SALT)`.
pub fn cmd_key(uuid: uuid::Uuid) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid.as_bytes());
    h.update(CMDKEY_SALT);
    h.finalize().into()
}

/// v2fly KDF: a cascade of HMAC-SHA256 whose keys are the path elements
/// over a root keyed "VMess AEAD KDF", applied to `key`.
///
/// Verified against the upstream test vector `kdf_test.go`.
pub fn vmess_kdf(key: &[u8], paths: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = Vec::with_capacity(paths.len() + 1);
    chain.push(KDF_ROOT);
    chain.extend_from_slice(paths);
    evaluate_chain(&chain, key)
}

/// Evaluate the nested HMAC chain for `message`.
fn evaluate_chain(chain: &[&[u8]], message: &[u8]) -> [u8; 32] {
    // innermost hash uses chain[0] as the HMAC key.
    fn level(chain: &[&[u8]], msg: &[u8]) -> [u8; 32] {
        if chain.len() == 1 {
            return hmac_sha256(chain[0], msg);
        }
        // HMAC(key = chain.last, hash = level(chain[..last])(.)
        let (last, rest) = chain.split_last().unwrap();
        let wrapped = |m: &[u8]| level(rest, m);
        hmac_with_hash(&wrapped, last, msg)
    }
    level(chain, message)
}

/// Plain HMAC-SHA256 (key, message) -> 32 bytes.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// HMAC over an arbitrary 32-byte hash function (RFC 2104, SHA-256-sized
/// block) — used to nest HMACs the way the v2fly KDF does.
fn hmac_with_hash(hash: &dyn Fn(&[u8]) -> [u8; 32], key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let ih = hash(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&ih);
    hash(&outer)
}

/// Count-based chunk nonce: `be_u16(count) || iv[2..12]`, incremented per
/// AEAD operation (length and payload each consume one).
#[derive(Debug)]
struct ChunkNonce {
    base_iv: [u8; 16],
    count: u16,
}

impl ChunkNonce {
    fn new(iv: [u8; 16]) -> Self {
        ChunkNonce { base_iv: iv, count: 0 }
    }

    fn advance(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..].copy_from_slice(&self.base_iv[2..12]);
        self.count = self.count.wrapping_add(1);
        n
    }
}

/// Generate the 16-byte encrypted auth ID:
/// `AES-ECB_{KDF16(cmdKey, "AES Auth ID Encryption")}(ts_be || rand4 || crc32_be)`.
fn create_auth_id(cmd_key: &[u8; 16], ts: i64) -> [u8; 16] {
    let mut body = [0u8; 16];
    body[..8].copy_from_slice(&ts.to_be_bytes());
    rand::rngs::OsRng.fill_bytes(&mut body[8..12]);
    let crc = crc32fast::hash(&body[..12]);
    body[12..].copy_from_slice(&crc.to_be_bytes());

    let key = &vmess_kdf(cmd_key, &[KDF_AUTH_ID_ENC_KEY])[..16];
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let block = aes::cipher::generic_array::GenericArray::from_mut_slice(&mut body[..]);
    cipher.encrypt_block(block);
    body
}

/// AEAD-seal the whole request header: `authID || len_enc || nonce || hdr_enc`.
fn seal_aead_header(cmd_key: &[u8; 16], header: &[u8]) -> io::Result<Vec<u8>> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let auth_id = create_auth_id(cmd_key, ts);
    let mut nonce = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let aead = crate::proto::aead::Aead::new(AeadKind::Aes128Gcm, &{
        let mut k = [0u8; 16];
        k.copy_from_slice(&vmess_kdf(cmd_key, &[KDF_HEADER_LEN_KEY, &auth_id, &nonce])[..16]);
        k
    })
    .map_err(io_other)?;
    let nonce_len: [u8; 12] = {
        let full = vmess_kdf(cmd_key, &[KDF_HEADER_LEN_NONCE, &auth_id, &nonce]);
        let mut n = [0u8; 12];
        n.copy_from_slice(&full[..12]);
        n
    };

    // Seal both parts with the real keys.
    let mut out = Vec::with_capacity(header.len() + 64);
    out.extend_from_slice(&auth_id);

    let len_plain = u16::try_from(header.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vmess header too large"))?
        .to_be_bytes();
    let mut len_ct = Vec::with_capacity(18);
    aead.seal(&nonce_len, &auth_id, &len_plain, &mut len_ct)
        .map_err(io_other)?;
    out.extend_from_slice(&len_ct);
    out.extend_from_slice(&nonce);

    let header_aead = crate::proto::aead::Aead::new(AeadKind::Aes128Gcm, &{
        let mut k = [0u8; 16];
        k.copy_from_slice(&vmess_kdf(cmd_key, &[KDF_HEADER_PAYLOAD_KEY, &auth_id, &nonce])[..16]);
        k
    })
    .map_err(io_other)?;
    let header_nonce: [u8; 12] = {
        let full = vmess_kdf(cmd_key, &[KDF_HEADER_PAYLOAD_NONCE, &auth_id, &nonce]);
        let mut n = [0u8; 12];
        n.copy_from_slice(&full[..12]);
        n
    };
    header_aead
        .seal(&header_nonce, &auth_id, header, &mut out)
        .map_err(io_other)?;
    Ok(out)
}

fn io_other(e: Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Body cipher state for one direction.
struct BodyCodec {
    kind: Option<crate::proto::aead::Aead>, // None for security::None
    nonce: ChunkNonce,
}

impl BodyCodec {
    fn new(security: VmessSecurity, key: [u8; 16], iv: [u8; 16]) -> Result<Self> {
        let kind = match security {
            VmessSecurity::Aes128Gcm => Some(crate::proto::aead::Aead::new(
                AeadKind::Aes128Gcm,
                &key,
            )?),
            VmessSecurity::Chacha20Poly1305 => {
                // v2fly: chacha key = MD5(key) || MD5(MD5(key))
                let mut k = Vec::with_capacity(32);
                let mut h = Md5::digest(key);
                k.extend_from_slice(&h);
                h = Md5::digest(h);
                k.extend_from_slice(&h);
                Some(crate::proto::aead::Aead::new(AeadKind::Chacha20Poly1305, &k)?)
            }
            VmessSecurity::None => None,
        };
        Ok(BodyCodec {
            kind,
            nonce: ChunkNonce::new(iv),
        })
    }

    fn seal_chunk(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
        match &self.kind {
            None => {
                let len = u16::try_from(plain.len())
                    .map_err(|_| Error::protocol("vmess chunk exceeds 65535 bytes"))?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(plain);
            }
            // The 2-byte frame length counts the CIPHERTEXT (payload+tag):
            // sing-vmess's StreamChunkReader reads exactly `length` bytes
            // and hands them to the AEAD reader.
            Some(_) => {
                let frame_len = plain
                    .len()
                    .checked_add(16)
                    .filter(|n| *n <= u16::MAX as usize)
                    .ok_or_else(|| Error::protocol("vmess chunk exceeds 65535 bytes"))?;
                out.extend_from_slice(&(frame_len as u16).to_be_bytes());
                if let Some(aead) = &self.kind {
                    aead.seal(&self.nonce.advance(), &[], plain, out)?;
                }
            }
        }
        Ok(())
    }

}

enum RespState {
    HeaderLen,
    HeaderPayload(u16),
    BodyLen,
    BodyPayload(u16),
}

/// A VMess AEAD client stream.
pub struct VmessStream {
    inner: BoxProxyStream,
    enc: BodyCodec,
    dec: BodyCodec,
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    expected_response_header: u8,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    pending_plain: usize,
    state: RespState,
}

impl VmessStream {
    /// Handshake on an established transport. `is_udp` selects the UDP
    /// command (payload then carries addressed datagrams).
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &VmessOut,
        target: &NetAddr,
        is_udp: bool,
    ) -> Result<Self> {
        let key = cmd_key(cfg.uuid);
        let mut rnd = [0u8; 33];
        rand::rngs::OsRng.fill_bytes(&mut rnd);
        let mut req_key = [0u8; 16];
        req_key.copy_from_slice(&rnd[..16]);
        let mut req_iv = [0u8; 16];
        req_iv.copy_from_slice(&rnd[16..32]);
        let response_header = rnd[32];

        let mut resp_key = [0u8; 16];
        resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
        let mut resp_iv = [0u8; 16];
        resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);

        // Instruction header.
        let padding_len = (rand::random::<u8>() % 16) as usize;
        let mut hdr = Vec::with_capacity(64);
        hdr.push(VERSION);
        hdr.extend_from_slice(&req_iv);
        hdr.extend_from_slice(&req_key);
        hdr.push(response_header);
        hdr.push(OPT_CHUNK_STREAM);
        hdr.push(((padding_len as u8) << 4) | cfg.security.wire());
        hdr.push(0); // reserved
        hdr.push(if is_udp { CMD_UDP } else { CMD_TCP });
        // mihomo's vmess (metacubex/sing-vmess) serializes the destination
        // PORT FIRST: `port_be16 || atyp || addr` — not the v2fly
        // atyp/addr/port order.
        crate::addr::encode_port_first_addr(&mut hdr, &target.host, target.port);
        hdr.extend(std::iter::repeat_n(0u8, padding_len));
        let checksum = fnv1a32(&hdr).to_be_bytes();
        hdr.extend_from_slice(&checksum);

        let wire = seal_aead_header(&key, &hdr)?;
        let mut transport = transport;
        transport.write_all(&wire).await?;
        Ok(VmessStream {
            inner: transport,
            enc: BodyCodec::new(cfg.security, req_key, req_iv)?,
            dec: BodyCodec::new(cfg.security, resp_key, resp_iv)?,
            resp_key,
            resp_iv,
            expected_response_header: response_header,
            rbuf: BytesMut::with_capacity(16 * 1024),
            plain: BytesMut::with_capacity(16 * 1024),
            wbuf: BytesMut::new(),
            pending_plain: 0,
            state: RespState::HeaderLen,
        })
    }

    fn advance_state(&mut self) -> Result<()> {
        const TAG: usize = 16;
        match self.state {
            RespState::HeaderLen => {
                let len_aead = crate::proto::aead::Aead::new(
                    AeadKind::Aes128Gcm,
                    &vmess_kdf(&self.resp_key, &[KDF_RESP_LEN_KEY])[..16],
                )?;
                let nonce: [u8; 12] = {
                    let full = vmess_kdf(&self.resp_iv, &[KDF_RESP_LEN_IV]);
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&full[..12]);
                    n
                };
                let pt = len_aead
                    .open(&nonce, &[], &self.rbuf[..18])
                    .map_err(|e| Error::protocol(format!("vmess resp len: {e}")))?;
                self.rbuf.advance(18);
                let len = u16::from_be_bytes([pt[0], pt[1]]);
                self.state = RespState::HeaderPayload(len);
            }
            RespState::HeaderPayload(len) => {
                let payload_aead = crate::proto::aead::Aead::new(
                    AeadKind::Aes128Gcm,
                    &vmess_kdf(&self.resp_key, &[KDF_RESP_PAYLOAD_KEY])[..16],
                )?;
                let nonce: [u8; 12] = {
                    let full = vmess_kdf(&self.resp_iv, &[KDF_RESP_PAYLOAD_IV]);
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&full[..12]);
                    n
                };
                let pt = payload_aead
                    .open(&nonce, &[], &self.rbuf[..len as usize + TAG])
                    .map_err(|e| Error::protocol(format!("vmess resp header: {e}")))?;
                self.rbuf.advance(len as usize + TAG);
                if pt.first() != Some(&self.expected_response_header) {
                    return Err(Error::protocol("vmess response header mismatch"));
                }
                // [0]=V [1]=opt [2]=cmd-id [3]=cmd-len [cmd bytes...]
                if pt.len() >= 4 && pt[2] != 0 {
                    let cmd_len = pt[3] as usize;
                    if pt.len() < 4 + cmd_len {
                        return Err(Error::protocol("vmess response command truncated"));
                    }
                }
                self.state = RespState::BodyLen;
            }
            RespState::BodyLen => {
                // Plain 2-byte frame length (only the AuthenticatedLength
                // option would seal it, which we never set).
                let need = 2;
                let len = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]);
                self.rbuf.advance(need);
                self.state = RespState::BodyPayload(len);
            }
            RespState::BodyPayload(len) => {
                // The frame length counts ciphertext INCLUSIVE of the tag.
                let n = len as usize;
                if n == 0 {
                    // Zero-length chunk: end of stream.
                    self.state = RespState::BodyLen;
                    return Ok(());
                }
                let raw = match &self.dec.kind {
                    None => self.rbuf[..n].to_vec(),
                    Some(aead) => {
                        if n < TAG {
                            return Err(Error::protocol("vmess body chunk shorter than a tag"));
                        }
                        aead
                            .open(&self.dec.nonce.advance(), &[], &self.rbuf[..n])
                            .map_err(|e| Error::protocol(format!("vmess body: {e}")))?
                    }
                };
                self.rbuf.advance(n);
                self.plain.extend_from_slice(&raw);
                self.state = RespState::BodyLen;
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
                RespState::HeaderLen => 18,
                RespState::HeaderPayload(l) => *l as usize + TAG,
                RespState::BodyLen => 2,
                // Frame length includes the tag already.
                RespState::BodyPayload(l) => *l as usize,
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

impl AsyncWrite for VmessStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            let mut out = Vec::with_capacity(buf.len() + 34);
            // Cap at 8 KiB plaintext per chunk (mirrors v2ray buffer sizes).
            let take = buf.len().min(8192);
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

impl VmessStream {
    /// Read exactly one body chunk (a UDP packet when the command is UDP).
    /// Chunk boundaries carry framing for VMess UDP, so callers must not
    /// use plain `read`, which may merge or split chunks.
    pub async fn read_packet(&mut self) -> crate::error::Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 1];
        loop {
            let n = self
                .read(&mut first)
                .await
                .map_err(|e| Error::network(format!("vmess packet read: {e}")))?;
            if n == 0 {
                return Err(Error::network("vmess: eof mid-packet"));
            }
            // The first decrypted byte implies the whole chunk is decoded
            // into `plain` — take the remainder.
            if !self.plain.is_empty() {
                let mut packet = Vec::with_capacity(1 + self.plain.len());
                packet.push(first[0]);
                packet.extend_from_slice(&self.plain);
                self.plain.clear();
                return Ok(packet);
            }
        }
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_matches_upstream_vector() {
        // v2fly proxy/vmess/aead/kdf_test.go
        let out = vmess_kdf(
            b"Demo Key for KDF Value Test",
            &[
                b"Demo Path for KDF Value Test".as_slice(),
                b"Demo Path for KDF Value Test2".as_slice(),
                b"Demo Path for KDF Value Test3".as_slice(),
            ],
        );
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"
        );
    }

    #[test]
    fn cmd_key_is_md5_of_uuid_bytes_and_salt() {
        let u = uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let mut h = Md5::new();
        h.update(u.as_bytes());
        h.update(CMDKEY_SALT);
        let expected: [u8; 16] = h.finalize().into();
        assert_eq!(cmd_key(u), expected);
    }

    #[test]
    fn chunk_nonce_layout() {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut n = ChunkNonce::new(iv);
        assert_eq!(&n.advance()[..2], &0u16.to_be_bytes());
        assert_eq!(&n.advance()[..2], &1u16.to_be_bytes());
        assert_eq!(&n.advance()[2..], &[3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn security_parse() {
        assert_eq!(
            VmessSecurity::parse("auto").unwrap(),
            VmessSecurity::Aes128Gcm
        );
        assert_eq!(
            VmessSecurity::parse("chacha20-poly1305").unwrap(),
            VmessSecurity::Chacha20Poly1305
        );
        assert!(VmessSecurity::parse("aes-256-cfb").is_err());
    }

    /// End-to-end header seal/open: parse what `seal_aead_header` produced
    /// using the server-side algorithm, verifying auth id CRC, FNV and the
    /// instruction fields.
    #[test]
    fn header_seal_open_roundtrip() {
        let u = uuid::Uuid::new_v4();
        let key = cmd_key(u);
        let target = NetAddr::domain("roundtrip.test", 443).unwrap();

        let mut hdr = Vec::new();
        hdr.push(VERSION);
        hdr.extend_from_slice(&[7u8; 16]); // iv
        hdr.extend_from_slice(&[9u8; 16]); // key
        hdr.push(0x42); // response header
        hdr.push(OPT_CHUNK_STREAM);
        hdr.push(SEC_AES128_GCM); // no padding
        hdr.push(0);
        hdr.push(CMD_TCP);
        crate::addr::encode_port_first_addr(&mut hdr, &target.host, target.port);
        hdr.extend_from_slice(&fnv1a32(&hdr).to_be_bytes());

        let sealed = seal_aead_header(&key, &hdr).unwrap();
        assert_eq!(&sealed[..16].len(), &16);

        // Server-side open.
        let auth_id: [u8; 16] = sealed[..16].try_into().unwrap();
        // Auth id decrypts and CRC-checks.
        let aes_key = &vmess_kdf(&key, &[KDF_AUTH_ID_ENC_KEY])[..16];
        let cipher = aes::Aes128::new_from_slice(aes_key).unwrap();
        use aes::cipher::BlockDecrypt;
        let mut block = aes::cipher::generic_array::GenericArray::clone_from_slice(&auth_id);
        cipher.decrypt_block(&mut block);
        let decrypted: [u8; 16] = block.into();
        assert_eq!(crc32fast::hash(&decrypted[..12]), u32::from_be_bytes(decrypted[12..].try_into().unwrap()));

        let nonce: [u8; 8] = sealed[34..42].try_into().unwrap();
        let len_aead = crate::proto::aead::Aead::new(
            AeadKind::Aes128Gcm,
            &vmess_kdf(&key, &[KDF_HEADER_LEN_KEY, &auth_id, &nonce])[..16],
        )
        .unwrap();
        let nonce_len: [u8; 12] = {
            let mut n = [0u8; 12];
            n.copy_from_slice(&vmess_kdf(&key, &[KDF_HEADER_LEN_NONCE, &auth_id, &nonce])[..12]);
            n
        };
        let len_pt = len_aead.open(&nonce_len, &auth_id, &sealed[16..34]).unwrap();
        let hlen = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        assert_eq!(hlen, hdr.len());

        let payload_aead = crate::proto::aead::Aead::new(
            AeadKind::Aes128Gcm,
            &vmess_kdf(&key, &[KDF_HEADER_PAYLOAD_KEY, &auth_id, &nonce])[..16],
        )
        .unwrap();
        let payload_nonce: [u8; 12] = {
            let mut n = [0u8; 12];
            n.copy_from_slice(
                &vmess_kdf(&key, &[KDF_HEADER_PAYLOAD_NONCE, &auth_id, &nonce])[..12],
            );
            n
        };
        let opened = payload_aead
            .open(&payload_nonce, &auth_id, &sealed[42..])
            .unwrap();
        assert_eq!(opened, hdr);
        // Instruction prefix: ver(1) iv(16) key(16) V(1) opt(1) sec(1) resv(1) cmd(1) = 38,
        // then the mihomo port-first destination.
        let (addr, used) = crate::addr::decode_port_first_addr(&opened[38..]).unwrap();
        assert_eq!(used + 38, opened.len() - 4, "fnv tail after address");
        assert_eq!(addr.host, target.host);
        assert_eq!(addr.port, 443);
        assert_eq!(fnv1a32(&opened[..opened.len() - 4]), u32::from_be_bytes(opened[opened.len() - 4..].try_into().unwrap()));
    }
}
