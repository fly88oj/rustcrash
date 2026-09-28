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
//! Request options: chunked streaming is required, and the two
//! chunk-framing options mihomo's client ALWAYS sets for AEAD securities
//! are served — `ChunkMasking` (0x04, the 2-byte chunk length XORed
//! with a SHAKE128 keystream seeded from the direction IV) and
//! `GlobalPadding` (0x08, a SHAKE128-derived padding appended inside
//! the chunk length) — see [`ChunkFraming`]. `AuthenticatedLength`
//! (0x10) is refused; no mihomo default sets it.
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
const OPT_GLOBAL_PADDING: u8 = 0x08;
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
        if opt & OPT_AUTH_LEN != 0 {
            return Err(Error::protocol(
                "vmess: authenticated length chunks are not supported",
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
        // convention), then the AEAD header KDF chain over those. The
        // response body rides the SAME request options (sing-vmess
        // service.go answers with CreateWriter(..., c.option)), so its
        // chunk framing is masked/padded with streams seeded from the
        // response IV — exactly what mihomo's client expects to read.
        let mut resp_key = [0u8; 16];
        resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
        let mut resp_iv = [0u8; 16];
        resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);
        let enc = VmessBody::new(security, resp_key, resp_iv, opt)?;
        let dec = VmessBody::new(security, req_key, req_iv, opt)?;

        // Response header: sealed length, then the sealed
        // [response-V, echoed option, no command, no command payload]
        // (sing-vmess writes its option byte back; the client checks
        // the first byte against its random response-V).
        let mut wire = Vec::with_capacity(64);
        let len_aead = Aead::new(
            AeadKind::Aes128Gcm,
            &kdf16(&resp_key, &[KDF_RESP_LEN_KEY]),
        )?;
        let len_nonce = kdf12(&resp_iv, &[KDF_RESP_LEN_IV]);
        let resp_hdr = [response_v, opt, 0u8, 0u8];
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

/// Read one AEAD body chunk as one datagram; `Ok(None)` at EOF or at
/// the zero-length end-of-stream marker. The chunk length is
/// masked/padded per the negotiated options exactly like the TCP body.
async fn read_body_datagram<R>(reader: &mut R, dec: &mut VmessBody) -> Result<Option<Vec<u8>>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 2];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let (mask, pad) = dec.framing_word();
    let total = (u16::from_be_bytes(len) ^ mask) as usize;
    let data = total
        .checked_sub(pad)
        .ok_or_else(|| Error::protocol("vmess udp: chunk length below its padding"))?;
    if data == 0 {
        return Ok(None); // end-of-stream marker
    }
    if data < TAG {
        return Err(Error::protocol("vmess udp: body chunk shorter than a tag"));
    }
    let mut ct = vec![0u8; total];
    reader.read_exact(&mut ct).await?;
    let plain = dec
        .aead
        .open(&dec.nonce.advance(), &[], &ct[..data])
        .map_err(|e| Error::protocol(format!("vmess udp body: {e}")))?;
    Ok(Some(plain))
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

// ---------------------------------------------------------------------------
// SHAKE128 (FIPS 202): the extendable-output function sing-vmess seeds
// with the direction IV to derive per-chunk length masks and padding
// lengths (`chunk_length_stream.go`). Hand-rolled because the engine
// carries no SHA-3 dependency and this is its only consumer; pinned to
// the NIST KATs (empty-message SHAKE128/256 and SHA3-256 vectors) in
// the tests below.
// ---------------------------------------------------------------------------

/// Keccak-f[1600] round constants.
const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rho rotation offsets paired with [`KECCAK_PILN`].
const KECCAK_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Pi lane permutation paired with [`KECCAK_ROTC`].
const KECCAK_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation (the classic in-place formulation:
/// theta, rho+pi, chi, iota).
fn keccak_f(st: &mut [u64; 25]) {
    for &rc in KECCAK_RC.iter() {
        let mut bc = [0u64; 5];
        // Theta.
        for (i, slot) in bc.iter_mut().enumerate() {
            *slot = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                st[j + i] ^= t;
            }
        }
        // Rho and Pi.
        let mut t = st[1];
        for i in 0..24 {
            let j = KECCAK_PILN[i];
            let tmp = st[j];
            st[j] = t.rotate_left(KECCAK_ROTC[i]);
            t = tmp;
        }
        // Chi.
        for j in (0..25).step_by(5) {
            bc.copy_from_slice(&st[j..j + 5]);
            for i in 0..5 {
                st[j + i] ^= !bc[(i + 1) % 5] & bc[(i + 2) % 5];
            }
        }
        // Iota.
        st[0] ^= rc;
    }
}

/// Squeeze `out.len()` bytes from Keccak-f[1600] over `seed` with the
/// given rate and domain-separation byte (0x1f = SHAKE, 0x06 = SHA3).
/// Only used with one-shot seeds shorter than the rate.
#[cfg(test)]
fn keccak_xof(domain: u8, rate: usize, seed: &[u8], out: &mut [u8]) {
    debug_assert!(seed.len() < rate && matches!(rate, 136 | 168));
    let mut st = [0u64; 25];
    // Absorb (single final block: seed || pad10*1 with the domain byte).
    let mut block = vec![0u8; rate];
    block[..seed.len()].copy_from_slice(seed);
    block[seed.len()] ^= domain;
    block[rate - 1] ^= 0x80;
    for (lane, state_lane) in st.iter_mut().enumerate().take(rate / 8) {
        let start = lane * 8;
        let mut word = [0u8; 8];
        word.copy_from_slice(&block[start..start + 8]);
        *state_lane ^= u64::from_le_bytes(word);
    }
    // Squeeze.
    let mut written = 0;
    while written < out.len() {
        keccak_f(&mut st);
        let take = (out.len() - written).min(rate);
        let end = written + take;
        let mut lane = 0;
        while written + lane * 8 + 8 <= end {
            out[written + lane * 8..written + lane * 8 + 8]
                .copy_from_slice(&st[lane].to_le_bytes());
            lane += 1;
        }
        // A tail shorter than one lane (callers use whole-byte words).
        if written + lane * 8 < end {
            let word = st[lane].to_le_bytes();
            out[written + lane * 8..end].copy_from_slice(&word[..end - written - lane * 8]);
        }
        written = end;
    }
}

/// SHAKE128 XOF state: absorb once at construction, then pull
/// big-endian u16 words off the squeeze stream chunk by chunk.
struct Shake128 {
    st: [u64; 25],
    out: [u8; 168],
    /// Bytes of `out` already consumed (== 168 → permute first).
    pos: usize,
}

impl Shake128 {
    /// SHAKE128(seed); seed must be shorter than the 168-byte rate.
    fn new(seed: &[u8]) -> Self {
        let mut s = Shake128 {
            st: [0u64; 25],
            out: [0u8; 168],
            pos: 168,
        };
        let mut block = [0u8; 168];
        block[..seed.len().min(168)].copy_from_slice(&seed[..seed.len().min(168)]);
        block[seed.len()] ^= 0x1f;
        block[167] ^= 0x80;
        for lane in 0..21 {
            let start = lane * 8;
            let mut word = [0u8; 8];
            word.copy_from_slice(&block[start..start + 8]);
            s.st[lane] ^= u64::from_le_bytes(word);
        }
        s
    }

    /// The next big-endian u16 off the squeeze stream (`binary.Read`
    /// into a uint16 in sing-vmess).
    fn next_u16(&mut self) -> u16 {
        if self.pos + 2 > 168 {
            keccak_f(&mut self.st);
            for lane in 0..21 {
                let word = self.st[lane].to_le_bytes();
                self.out[lane * 8..lane * 8 + 8].copy_from_slice(&word);
            }
            self.pos = 0;
        }
        let n = u16::from_be_bytes([self.out[self.pos], self.out[self.pos + 1]]);
        self.pos += 2;
        n
    }
}

/// sing-vmess's per-chunk length framing (chunk_length_stream.go):
/// the 2-byte chunk length is XOR-masked and/or the chunk carries
/// SHAKE-derived padding counted inside the length. The stream is
/// seeded with the direction's 16-byte IV; with BOTH options sing uses
/// ONE stream (the padding instance doubles as the mask instance),
/// reading the padding word first and the mask word second — mirrored
/// here so every option combination stays byte-compatible.
enum ChunkFraming {
    /// No framing options: plain `be16(len || ct || tag)` chunks.
    Plain,
    /// RequestOptionChunkMasking (0x04): `be16(len ^ mask)`.
    Mask(Shake128),
    /// RequestOptionGlobalPadding (0x08): `be16(len)` with `len %`-64
    /// random padding trailing the ciphertext inside the length.
    Pad(Shake128),
    /// Both: one shared stream — padding word, then mask word.
    MaskPad(Shake128),
}

impl ChunkFraming {
    /// From the request option byte; the direction IV seeds the stream.
    fn from_opt(opt: u8, iv: [u8; 16]) -> Self {
        match (
            opt & OPT_CHUNK_MASKING != 0,
            opt & OPT_GLOBAL_PADDING != 0,
        ) {
            (true, true) => ChunkFraming::MaskPad(Shake128::new(&iv)),
            (true, false) => ChunkFraming::Mask(Shake128::new(&iv)),
            (false, true) => ChunkFraming::Pad(Shake128::new(&iv)),
            (false, false) => ChunkFraming::Plain,
        }
    }

    /// `(mask, padding_len)` for the next chunk, in wire order.
    fn next(&mut self) -> (u16, usize) {
        match self {
            ChunkFraming::Plain => (0, 0),
            ChunkFraming::Mask(s) => (s.next_u16(), 0),
            ChunkFraming::Pad(s) => (0, (s.next_u16() % 64) as usize),
            ChunkFraming::MaskPad(s) => {
                let pad = (s.next_u16() % 64) as usize;
                (s.next_u16(), pad)
            }
        }
    }
}

/// Body cipher for one direction: 2-byte ciphertext length then one AEAD
/// block (the length counts the tag; mirrors `proto::vmess::BodyCodec`),
/// optionally length-masked and padded per [`ChunkFraming`].
struct VmessBody {
    aead: Aead,
    nonce: VmessNonce,
    framing: ChunkFraming,
}

impl VmessBody {
    fn new(security: u8, key: [u8; 16], iv: [u8; 16], opt: u8) -> Result<Self> {
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
            framing: ChunkFraming::from_opt(opt, iv),
        })
    }

    fn seal_chunk(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let (mask, pad) = self.framing.next();
        let frame_len = plain
            .len()
            .checked_add(TAG + pad)
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or_else(|| Error::protocol("vmess chunk exceeds 65535 bytes"))?;
        out.extend_from_slice(&((frame_len as u16) ^ mask).to_be_bytes());
        self.aead.seal(&self.nonce.advance(), &[], plain, out)?;
        // Padding trails the ciphertext INSIDE the masked length
        // (sing-vmess StreamChunkWriter.WriteBuffer).
        if pad > 0 {
            let start = out.len();
            out.resize(start + pad, 0);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out[start..]);
        }
        Ok(())
    }

    /// Decode a wire length just read: `(mask, padding_len)` for it.
    fn framing_word(&mut self) -> (u16, usize) {
        self.framing.next()
    }
}

enum ReadState {
    /// Waiting for the 2-byte chunk length (masked per [`ChunkFraming`]).
    Len,
    /// Reading `n` wire bytes of which the trailing `pad` are padding.
    Payload { n: usize, pad: usize },
    /// The peer's zero-length end-of-stream chunk.
    End,
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
                let wire = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]);
                self.rbuf.advance(2);
                let (mask, pad) = self.dec.framing_word();
                let total = (wire ^ mask) as usize;
                let data = total
                    .checked_sub(pad)
                    .ok_or_else(|| Error::protocol("vmess: chunk length below its padding"))?;
                if data == 0 {
                    // sing-vmess's StreamChunkReader reads this as EOF.
                    self.state = ReadState::End;
                    return Ok(());
                }
                self.state = ReadState::Payload { n: total, pad };
            }
            ReadState::Payload { n, pad } => {
                let data = n - pad;
                if data < TAG {
                    return Err(Error::protocol("vmess body chunk shorter than a tag"));
                }
                let pt = self
                    .dec
                    .aead
                    .open(&self.dec.nonce.advance(), &[], &self.rbuf[..data])
                    .map_err(|e| Error::protocol(format!("vmess body: {e}")))?;
                // Advance past ciphertext AND the trailing padding.
                self.rbuf.advance(n);
                self.plain.extend_from_slice(&pt);
                self.state = ReadState::Len;
            }
            ReadState::End => {}
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
                ReadState::Payload { n, .. } => *n,
                // The end-of-stream chunk: deliver EOF once the decoded
                // bytes are drained (plain is empty here).
                ReadState::End => return Poll::Ready(Ok(())),
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

    // --- SHAKE128 / Keccak-f[1600] correctness ---------------------------

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The NIST KATs the hand-rolled sponge must reproduce: the
    /// empty-message SHAKE128/SHAKE256 prefixes and SHA3-256 for "" and
    /// "abc" (same permutation, different domain bytes and rates — a
    /// wrong round constant, rotation or lane order breaks all four).
    #[test]
    fn keccak_matches_nist_vectors() {
        let mut out = [0u8; 32];
        keccak_xof(0x1f, 168, b"", &mut out);
        assert_eq!(
            hex(&out),
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
            "SHAKE128(\"\")"
        );
        keccak_xof(0x1f, 136, b"", &mut out);
        assert_eq!(
            hex(&out[..32]),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
            "SHAKE256(\"\")"
        );
        keccak_xof(0x06, 136, b"", &mut out);
        assert_eq!(
            hex(&out),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "SHA3-256(\"\")"
        );
        keccak_xof(0x06, 136, b"abc", &mut out);
        assert_eq!(
            hex(&out),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "SHA3-256(\"abc\")"
        );
    }

    /// The incremental u16 squeeze must equal the one-shot XOF output,
    /// including across the 168-byte block boundary.
    #[test]
    fn shake128_streaming_matches_one_shot() {
        let mut oneshot = vec![0u8; 400];
        keccak_xof(0x1f, 168, b"vmess-chunk-masking-seed", &mut oneshot);
        let mut s = Shake128::new(b"vmess-chunk-masking-seed");
        for (i, word) in (0..200u16).map(|i| i * 7).enumerate() {
            let _ = word;
            let got = s.next_u16().to_be_bytes();
            assert_eq!(got, &oneshot[i * 2..i * 2 + 2], "word {i}");
        }
    }

    // --- mihomo-shaped (sing-vmess) client sessions -----------------------

    /// The per-chunk framing word order, mirrored from sing-vmess
    /// chunk_length_stream.go: the padding length word is read BEFORE
    /// the mask word, from one shared SHAKE stream when both options
    /// are set (and no stream at all when neither is).
    fn sing_framing_word(
        shake: &mut Option<Shake128>,
        mask: bool,
        pad: bool,
    ) -> (u16, usize) {
        let Some(s) = shake.as_mut() else {
            return (0, 0);
        };
        let padding = if pad {
            (s.next_u16() % 64) as usize
        } else {
            0
        };
        let mask = if mask { s.next_u16() } else { 0 };
        (mask, padding)
    }

    /// One count-based AEAD body nonce: `be16(count) || iv[2..12]`.
    fn sing_chunk_nonce(count: u16, iv: &[u8; 16]) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&count.to_be_bytes());
        n[2..].copy_from_slice(&iv[2..12]);
        n
    }

    /// A minimal client speaking EXACTLY the wire shapes metacubex
    /// sing-vmess produces (client.go writeHandshake for the AEAD
    /// header; chunk_length_stream.go for the framed body) — the shapes
    /// the real mihomo client sends. Masking/padding follow the `opt`
    /// handed in, so every option combination the server accepts is
    /// exercisable.
    struct SingClient {
        stream: TcpStream,
        enc: Aead,
        enc_count: u16,
        req_iv: [u8; 16],
        resp_key: [u8; 16],
        dec: Aead,
        dec_count: u16,
        resp_iv: [u8; 16],
        resp_v: u8,
        opt: u8,
        up_shake: Option<Shake128>,
        down_shake: Option<Shake128>,
    }

    impl SingClient {
        async fn connect(
            uuid: &str,
            addr: SocketAddr,
            opt: u8,
            cmd: u8,
            target: &NetAddr,
        ) -> Result<Self> {
            use aes::cipher::BlockEncrypt;
            let mut stream = TcpStream::connect(addr).await?;
            let key = cmd_key(uuid::Uuid::parse_str(uuid).unwrap());
            let mut rnd = [0u8; 33];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rnd);
            let mut req_key = [0u8; 16];
            req_key.copy_from_slice(&rnd[..16]);
            let mut req_iv = [0u8; 16];
            req_iv.copy_from_slice(&rnd[16..32]);
            let resp_v = rnd[32];
            let mut resp_key = [0u8; 16];
            resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
            let mut resp_iv = [0u8; 16];
            resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);

            // Instruction header: V iv key respV opt P resv cmd addr
            // pad fnv — P carries (header-pad<<4 | security).
            let header_pad = 3usize;
            let mut hdr = Vec::with_capacity(64);
            hdr.push(VERSION);
            hdr.extend_from_slice(&req_iv);
            hdr.extend_from_slice(&req_key);
            hdr.push(resp_v);
            hdr.push(opt);
            hdr.push(((header_pad as u8) << 4) | SEC_AES128_GCM);
            hdr.push(0);
            hdr.push(cmd);
            encode_port_first_addr(&mut hdr, &target.host, target.port);
            hdr.extend(std::iter::repeat_n(0u8, header_pad));
            let checksum = fnv1a32(&hdr).to_be_bytes();
            hdr.extend_from_slice(&checksum);

            // Auth id: AES-ECB(ts || rand4 || crc32).
            let mut body = [0u8; 16];
            body[..8].copy_from_slice(&(now_secs() as i64).to_be_bytes());
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut body[8..12]);
            let crc = crc32fast::hash(&body[..12]);
            body[12..].copy_from_slice(&crc.to_be_bytes());
            let cipher = aes::Aes128::new_from_slice(&kdf16(&key, &[KDF_AUTH_ID_ENC_KEY]))
                .map_err(|e| Error::crypto(e.to_string()))?;
            let mut block = aes::cipher::generic_array::GenericArray::from(body);
            cipher.encrypt_block(&mut block);
            let auth_id: [u8; 16] = block.into();

            let mut nonce8 = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce8);

            let len_plain = (hdr.len() as u16).to_be_bytes();
            let len_aead = Aead::new(
                AeadKind::Aes128Gcm,
                &kdf16(&key, &[KDF_HEADER_LEN_KEY, &auth_id, &nonce8]),
            )?;
            let mut len_ct = Vec::with_capacity(18);
            len_aead.seal(
                &kdf12(&key, &[KDF_HEADER_LEN_NONCE, &auth_id, &nonce8]),
                &auth_id,
                &len_plain,
                &mut len_ct,
            )?;
            let hdr_aead = Aead::new(
                AeadKind::Aes128Gcm,
                &kdf16(&key, &[KDF_HEADER_PAYLOAD_KEY, &auth_id, &nonce8]),
            )?;
            let mut hdr_ct = Vec::with_capacity(hdr.len() + TAG);
            hdr_aead.seal(
                &kdf12(&key, &[KDF_HEADER_PAYLOAD_NONCE, &auth_id, &nonce8]),
                &auth_id,
                &hdr,
                &mut hdr_ct,
            )?;

            let mut wire = Vec::with_capacity(42 + hdr_ct.len());
            wire.extend_from_slice(&auth_id);
            wire.extend_from_slice(&len_ct);
            wire.extend_from_slice(&nonce8);
            wire.extend_from_slice(&hdr_ct);
            stream.write_all(&wire).await?;
            stream.flush().await?;

            Ok(SingClient {
                stream,
                enc: Aead::new(AeadKind::Aes128Gcm, &req_key)?,
                enc_count: 0,
                req_iv,
                resp_key,
                dec: Aead::new(AeadKind::Aes128Gcm, &resp_key)?,
                dec_count: 0,
                resp_iv,
                resp_v,
                opt,
                up_shake: if opt & (OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING) != 0 {
                    Some(Shake128::new(&req_iv))
                } else {
                    None
                },
                down_shake: if opt & (OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING) != 0 {
                    Some(Shake128::new(&resp_iv))
                } else {
                    None
                },
            })
        }

        async fn send_chunk(&mut self, plain: &[u8]) -> Result<()> {
            let (mask, pad) = sing_framing_word(
                &mut self.up_shake,
                self.opt & OPT_CHUNK_MASKING != 0,
                self.opt & OPT_GLOBAL_PADDING != 0,
            );
            let total = plain.len() + TAG + pad;
            let mut out = Vec::with_capacity(total + 2);
            out.extend_from_slice(&((total as u16) ^ mask).to_be_bytes());
            self.enc.seal(
                &sing_chunk_nonce(self.enc_count, &self.req_iv),
                &[],
                plain,
                &mut out,
            )?;
            self.enc_count = self.enc_count.wrapping_add(1);
            if pad > 0 {
                let start = out.len();
                out.resize(start + pad, 0);
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out[start..]);
            }
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
            Ok(())
        }

        /// Read and verify the server's sealed response header: the
        /// 18-byte sealed length, then the sealed
        /// `[response-V, echoed option, 0, 0]` payload.
        async fn read_response_header(&mut self) -> Result<()> {
            use tokio::io::AsyncReadExt;
            let len_aead = Aead::new(
                AeadKind::Aes128Gcm,
                &kdf16(&self.resp_key, &[KDF_RESP_LEN_KEY]),
            )?;
            let mut buf = [0u8; 18];
            self.stream.read_exact(&mut buf).await?;
            let pt = len_aead.open(&kdf12(&self.resp_iv, &[KDF_RESP_LEN_IV]), &[], &buf)?;
            let hlen = u16::from_be_bytes([pt[0], pt[1]]) as usize;
            let payload_aead = Aead::new(
                AeadKind::Aes128Gcm,
                &kdf16(&self.resp_key, &[KDF_RESP_PAYLOAD_KEY]),
            )?;
            let mut hdr_ct = vec![0u8; hlen + TAG];
            self.stream.read_exact(&mut hdr_ct).await?;
            let hdr = payload_aead.open(
                &kdf12(&self.resp_iv, &[KDF_RESP_PAYLOAD_IV]),
                &[],
                &hdr_ct,
            )?;
            assert_eq!(hdr[0], self.resp_v, "response header byte mismatch");
            assert_eq!(hdr[1], self.opt, "server must echo the request options");
            Ok(())
        }

        /// Read one framed (masked/padded) response body chunk.
        async fn read_chunk(&mut self) -> Result<Vec<u8>> {
            use tokio::io::AsyncReadExt;
            let mut len = [0u8; 2];
            self.stream.read_exact(&mut len).await?;
            let (mask, pad) = sing_framing_word(
                &mut self.down_shake,
                self.opt & OPT_CHUNK_MASKING != 0,
                self.opt & OPT_GLOBAL_PADDING != 0,
            );
            let total = (u16::from_be_bytes(len) ^ mask) as usize;
            let data = total
                .checked_sub(pad)
                .ok_or_else(|| Error::protocol("chunk length below its padding"))?;
            let mut wire = vec![0u8; total];
            self.stream.read_exact(&mut wire).await?;
            let plain = self.dec.open(
                &sing_chunk_nonce(self.dec_count, &self.resp_iv),
                &[],
                &wire[..data],
            )?;
            self.dec_count = self.dec_count.wrapping_add(1);
            Ok(plain)
        }
    }

    /// mihomo's default for AEAD securities: option 0x05 — chunk
    /// stream + chunk masking (sing-vmess dialRaw). The old server
    /// rejected this outright, which is why the real mihomo client
    /// completed the dial but never saw payload.
    #[tokio::test]
    async fn mihomo_style_masked_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut c = SingClient::connect(
            &uuid,
            addr,
            OPT_CHUNK_STREAM | OPT_CHUNK_MASKING,
            CMD_TCP,
            &target,
        )
        .await
        .unwrap();
        c.send_chunk(b"ping").await.unwrap();
        c.read_response_header().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), c.read_chunk())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(got, b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    /// Masking + global padding (option 0x0d, mihomo's
    /// `global-padding: true`): one SHAKE stream yields the padding
    /// word then the mask word per chunk, in both directions, and the
    /// random padding trails the ciphertext inside the masked length.
    #[tokio::test]
    async fn mihomo_style_masked_padded_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut c = SingClient::connect(
            &uuid,
            addr,
            OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING,
            CMD_TCP,
            &target,
        )
        .await
        .unwrap();
        c.send_chunk(b"first").await.unwrap();
        c.send_chunk(b"-second").await.unwrap();
        c.read_response_header().await.unwrap();
        let a = tokio::time::timeout(Duration::from_secs(5), c.read_chunk())
            .await
            .expect("timeout")
            .unwrap();
        let b = tokio::time::timeout(Duration::from_secs(5), c.read_chunk())
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(a, b"first");
        assert_eq!(b, b"-second");
        assert_eq!(capture.targets(), vec![target]);
    }

    /// The UDP command with masking: datagram chunks are framed with
    /// the same masked lengths in both directions.
    #[tokio::test]
    async fn mihomo_style_masked_udp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, "auto").await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let placeholder =
            NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut c = SingClient::connect(
            &uuid,
            addr,
            OPT_CHUNK_STREAM | OPT_CHUNK_MASKING,
            CMD_UDP,
            &placeholder,
        )
        .await
        .unwrap();
        let mut frame = Vec::new();
        encode_port_first_addr(&mut frame, &target.host, target.port);
        frame.extend_from_slice(b"udp-ping");
        c.send_chunk(&frame).await.unwrap();
        c.read_response_header().await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), c.read_chunk())
            .await
            .expect("timeout")
            .unwrap();
        let (from, used) = decode_port_first_addr(&reply).unwrap();
        assert_eq!(from, target);
        assert_eq!(&reply[used..], b"udp-ping");
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.relayed(), 0);
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