//! TUIC v5 outbound over QUIC, ported from the sing-quic tuic client
//! and the TUIC v5 protocol specification (EAimTY/tuic SPEC.md):
//! authentication rides a unidirectional stream carrying the raw UUID
//! and a 32-byte token derived from the TLS keying material exporter
//! (label = raw UUID bytes, context = raw password); TCP relays open a
//! bidirectional stream whose first bytes are the version/command
//! header plus the target address (address first, then port, with
//! family bytes 0x00/0x01/0x02/0xff); UDP relays send Packet commands
//! as QUIC datagrams (native mode) or over unidirectional streams
//! (quic mode), with Dissociate releasing a session and datagram
//! heartbeats keeping the connection alive. The server never responds
//! to any command — errors surface as stream resets or connection
//! closure.

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::quic::{self, QuicDial, QuicStream};
use crate::stream::BoxProxyStream;

/// Protocol version byte.
const VERSION: u8 = 5;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;
/// Upstream ALPN for TUIC v5.
pub const ALPN: &str = "tuic";
/// Authenticate frame size: VER + TYPE + UUID + TOKEN.
const AUTHENTICATE_LEN: usize = 2 + 16 + 32;
/// Auth token length (RFC 5705 exporter output).
const AUTH_TOKEN_LEN: usize = 32;
/// Native-mode fragmentation budget, mirroring the upstream client's
/// `1200 - 3` UDP MTU.
const UDP_MTU: usize = 1200 - 3;

/// Address family bytes (sing's serializer, used by the TUIC wire
/// format).
const ATYP_FQDN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
const ATYP_EMPTY: u8 = 0xff;

/// How UDP packets are relayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UdpRelayMode {
    /// QUIC datagrams (0-RTT full-cone forwarding).
    #[default]
    Native,
    /// Unidirectional QUIC streams.
    Quic,
}

impl UdpRelayMode {
    /// Parse the config string form (`udp-relay-mode`).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "native" => Ok(UdpRelayMode::Native),
            "quic" => Ok(UdpRelayMode::Quic),
            other => Err(Error::config(format!(
                "tuic: unknown udp relay mode {other:?} (native|quic)"
            ))),
        }
    }
}

/// Outbound TUIC v5 endpoint.
#[derive(Debug, Clone)]
pub struct TuicCfg {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
    pub udp_relay_mode: UdpRelayMode,
}

/// Connect and authenticate; the returned connection serves TCP and UDP
/// relays until closed.
pub async fn connect(cfg: &TuicCfg) -> Result<quinn::Connection> {
    let dial = QuicDial {
        server: cfg.server.clone(),
        port: cfg.port,
        sni: cfg.sni.clone(),
        alpn: vec![ALPN.to_string()],
        skip_verify: cfg.skip_verify,
        udp_relay: true,
        congestion_brutal_bps: None,
    };
    let conn = quic::dial(&dial).await?;
    authenticate(&conn, cfg).await?;
    Ok(conn)
}

/// [`connect`] with ECH (mihomo `ech-opts` on a TUIC outbound): the QUIC
/// dial runs on the engine's own TLS 1.3 stack
/// ([`crate::quic::tls13`]) with the ECH cover — the inner hello carries
/// the real SNI and ALPN `tuic`. The `Authenticate` token (TLS exporter)
/// is computed by the same RFC 8446 §7.5 exporter the custom session
/// implements, so the protocol above the handshake is unchanged.
pub async fn connect_ech(
    cfg: &TuicCfg,
    opts: &crate::proto::ech::EchOptions,
) -> Result<quinn::Connection> {
    let selection = quic::ech_selection(opts)?;
    let dial = QuicDial {
        server: cfg.server.clone(),
        port: cfg.port,
        sni: cfg.sni.clone(),
        alpn: vec![ALPN.to_string()],
        skip_verify: cfg.skip_verify,
        udp_relay: true,
        congestion_brutal_bps: None,
    };
    let conn = quic::dial_ech(&dial, selection).await?;
    authenticate(&conn, cfg).await?;
    Ok(conn)
}

/// Send the Authenticate command on a unidirectional stream:
/// `VER(5) || TYPE(0) || UUID(16) || TOKEN(32)` where TOKEN is
/// TLS-Exporter(label = raw UUID, context = raw password, 32 bytes).
async fn authenticate(conn: &quinn::Connection, cfg: &TuicCfg) -> Result<()> {
    let mut token = [0u8; AUTH_TOKEN_LEN];
    conn.export_keying_material(&mut token, cfg.uuid.as_bytes(), cfg.password.as_bytes())
        .map_err(|e| Error::crypto(format!("tuic auth token export: {e:?}")))?;
    let frame = build_authenticate_frame(cfg.uuid, &token);
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("tuic auth stream: {e}")))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| Error::network(format!("tuic auth write: {e}")))?;
    stream
        .finish()
        .map_err(|e| Error::network(format!("tuic auth fin: {e}")))?;
    tracing::debug!(target: "engine", "tuic v5 authenticated as {}", cfg.uuid);
    Ok(())
}

fn build_authenticate_frame(uuid: uuid::Uuid, token: &[u8; AUTH_TOKEN_LEN]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(AUTHENTICATE_LEN);
    frame.extend_from_slice(&[VERSION, CMD_AUTHENTICATE]);
    frame.extend_from_slice(uuid.as_bytes());
    frame.extend_from_slice(token);
    frame
}

/// Open a TCP relay: bidirectional stream, first frame
/// `VER(5) || TYPE(1) || ADDR`, then raw payload in both directions
/// (the server never acknowledges the connect command).
pub async fn tcp_stream(conn: &quinn::Connection, target: &NetAddr) -> Result<BoxProxyStream> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::network(format!("tuic open stream: {e}")))?;
    let mut stream = QuicStream::new(send, recv);
    let mut header = Vec::with_capacity(1 + 19 + 2);
    header.extend_from_slice(&[VERSION, CMD_CONNECT]);
    encode_addr_port(&mut header, Some(target));
    tokio::io::AsyncWriteExt::write_all(&mut stream, &header).await?;
    Ok(Box::new(stream))
}

/// Send one UDP packet in native mode: Packet command(s) as QUIC
/// datagrams, fragmenting payloads that exceed the datagram budget
/// (`FRAG_TOTAL`/`FRAG_ID` reassemble them; later fragments omit the
/// address, per spec).
pub async fn udp_send_native(
    conn: &quinn::Connection,
    session_id: u16,
    packet_id: u16,
    target: &NetAddr,
    data: &[u8],
) -> Result<()> {
    for fragment in fragment_packet(session_id, packet_id, target, data) {
        conn.send_datagram(Bytes::from(fragment))
            .map_err(|e| Error::network(format!("tuic udp datagram: {e}")))?;
    }
    Ok(())
}

/// Send one UDP packet in quic mode: one Packet command on a fresh
/// unidirectional stream (never fragmented upstream).
pub async fn udp_send_quic(
    conn: &quinn::Connection,
    session_id: u16,
    packet_id: u16,
    target: &NetAddr,
    data: &[u8],
) -> Result<()> {
    let frame = encode_packet_frame(session_id, packet_id, 0, 1, Some(target), data);
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("tuic udp stream: {e}")))?;
    stream
        .write_all(&frame)
        .await
        .map_err(|e| Error::network(format!("tuic udp write: {e}")))?;
    stream
        .finish()
        .map_err(|e| Error::network(format!("tuic udp fin: {e}")))?;
    Ok(())
}

/// Release a UDP relay session: `VER || TYPE(3) || ASSOC_ID(u16be)` on
/// a unidirectional stream.
pub async fn dissociate(conn: &quinn::Connection, session_id: u16) -> Result<()> {
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("tuic dissociate stream: {e}")))?;
    let frame = [VERSION, CMD_DISSOCIATE, (session_id >> 8) as u8, session_id as u8];
    stream
        .write_all(&frame)
        .await
        .map_err(|e| Error::network(format!("tuic dissociate write: {e}")))?;
    stream
        .finish()
        .map_err(|e| Error::network(format!("tuic dissociate fin: {e}")))?;
    Ok(())
}

/// Keep-alive: a Heartbeat command (`VER || TYPE(4)`) as a QUIC
/// datagram.
pub async fn heartbeat(conn: &quinn::Connection) -> Result<()> {
    conn.send_datagram(Bytes::from(heartbeat_frame().to_vec()))
        .map_err(|e| Error::network(format!("tuic heartbeat: {e}")))
}

fn heartbeat_frame() -> [u8; 2] {
    [VERSION, CMD_HEARTBEAT]
}

/// Encode the sing address form: `FAMILY || ADDR || PORT(be)` (the port
/// is omitted for the empty family).
fn encode_addr_port(buf: &mut Vec<u8>, target: Option<&NetAddr>) {
    match target.map(|t| &t.host) {
        Some(Host::Domain(d)) => {
            let d = d.as_bytes();
            let len = d.len().min(255);
            buf.push(ATYP_FQDN);
            buf.push(len as u8);
            buf.extend_from_slice(&d[..len]);
        }
        Some(Host::Ip(IpAddr::V4(v4))) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Some(Host::Ip(IpAddr::V6(v6))) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
        None => buf.push(ATYP_EMPTY),
    }
    if let Some(t) = target {
        buf.extend_from_slice(&t.port.to_be_bytes());
    }
}

/// Parse the sing address form; `None` for the empty family (a
/// non-first UDP fragment). Returns the address and bytes consumed.
pub fn decode_addr_port(data: &[u8]) -> Result<(Option<NetAddr>, usize)> {
    let Some(&atyp) = data.first() else {
        return Err(Error::protocol("tuic addr: empty"));
    };
    let mut off = 1usize;
    let host = match atyp {
        ATYP_EMPTY => return Ok((None, off)),
        ATYP_FQDN => {
            let Some(&len) = data.get(off) else {
                return Err(Error::protocol("tuic addr: short domain length"));
            };
            off += 1;
            let Some(bytes) = data.get(off..off + len as usize) else {
                return Err(Error::protocol("tuic addr: short domain"));
            };
            off += len as usize;
            let s = std::str::from_utf8(bytes)
                .map_err(|_| Error::protocol("tuic addr: domain not utf-8"))?;
            Host::Domain(s.to_ascii_lowercase())
        }
        ATYP_IPV4 => {
            let Some(o) = data.get(off..off + 4) else {
                return Err(Error::protocol("tuic addr: short ipv4"));
            };
            off += 4;
            Host::Ip(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
        }
        ATYP_IPV6 => {
            let Some(o) = data.get(off..off + 16) else {
                return Err(Error::protocol("tuic addr: short ipv6"));
            };
            off += 16;
            let mut b = [0u8; 16];
            b.copy_from_slice(o);
            Host::Ip(IpAddr::V6(b.into()))
        }
        other => return Err(Error::protocol(format!("tuic addr: bad atyp {other:#x}"))),
    };
    let Some(port) = data.get(off..off + 2) else {
        return Err(Error::protocol("tuic addr: short port"));
    };
    off += 2;
    let port = u16::from_be_bytes([port[0], port[1]]);
    Ok((Some(NetAddr::new(host, port)), off))
}

/// Encode a Packet command frame:
/// `VER || TYPE(2) || ASSOC_ID(u16be) || PKT_ID(u16be) ||
/// FRAG_TOTAL(u8) || FRAG_ID(u8) || SIZE(u16be) || ADDR || DATA`.
fn encode_packet_frame(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: Option<&NetAddr>,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + 19 + data.len());
    buf.extend_from_slice(&[VERSION, CMD_PACKET]);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_total);
    buf.push(frag_id);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    encode_addr_port(&mut buf, target);
    buf.extend_from_slice(data);
    buf
}

/// A decoded Packet command frame (the form the server sends back for
/// UDP relays).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame<'a> {
    pub session_id: u16,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_total: u8,
    /// `None` on non-first fragments (empty address family).
    pub addr: Option<NetAddr>,
    pub data: &'a [u8],
}

/// Parse a Packet command frame into its header fields and data slice.
pub fn decode_packet_frame(msg: &[u8]) -> Result<PacketFrame<'_>> {
    if msg.len() < 10 {
        return Err(Error::protocol("tuic packet: short header"));
    }
    if msg[0] != VERSION {
        return Err(Error::protocol(format!("tuic packet: bad version {}", msg[0])));
    }
    if msg[1] != CMD_PACKET {
        return Err(Error::protocol(format!("tuic packet: bad command {}", msg[1])));
    }
    let session_id = u16::from_be_bytes([msg[2], msg[3]]);
    let packet_id = u16::from_be_bytes([msg[4], msg[5]]);
    let frag_total = msg[6];
    let frag_id = msg[7];
    let data_len = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let (addr, n) = decode_addr_port(&msg[10..])?;
    let data = msg
        .get(10 + n..10 + n + data_len)
        .ok_or_else(|| Error::protocol("tuic packet: short data"))?;
    Ok(PacketFrame {
        session_id,
        packet_id,
        frag_id,
        frag_total,
        addr,
        data,
    })
}

/// The on-wire size of a Packet frame header for a full target address
/// (command bytes + fixed fields + address family + address + port).
fn packet_header_size(target: &NetAddr) -> usize {
    10 + match &target.host {
        Host::Domain(d) => 4 + d.len().min(255),
        Host::Ip(IpAddr::V4(_)) => 7,
        Host::Ip(IpAddr::V6(_)) => 19,
    }
}

/// Split one payload into Packet frames fitting [`UDP_MTU`],
/// mirroring upstream `fragUDPMessage`: uniform chunks sized by the
/// first fragment's header, later fragments carry the empty address.
fn fragment_packet(
    session_id: u16,
    packet_id: u16,
    target: &NetAddr,
    data: &[u8],
) -> Vec<Vec<u8>> {
    let budget = UDP_MTU.saturating_sub(packet_header_size(target));
    if data.len() <= budget || budget == 0 {
        return vec![encode_packet_frame(session_id, packet_id, 0, 1, Some(target), data)];
    }
    let mut fragments = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + budget).min(data.len());
        fragments.push(&data[off..end]);
        off = end;
    }
    let total = fragments.len() as u8;
    fragments
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let addr = if i == 0 { Some(target) } else { None };
            encode_packet_frame(session_id, packet_id, i as u8, total, addr, chunk)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn addr_roundtrip_all_families() {
        let targets = [
            NetAddr::domain("example.com", 443).unwrap(),
            NetAddr::new(
                Host::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                8080,
            ),
            NetAddr::new(Host::Ip(IpAddr::V6("2001:db8::1".parse().unwrap())), 53),
        ];
        for t in targets {
            let mut buf = Vec::new();
            encode_addr_port(&mut buf, Some(&t));
            let (got, used) = decode_addr_port(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(got.as_ref(), Some(&t));
        }
        // Empty family: one byte, no port.
        let mut buf = Vec::new();
        encode_addr_port(&mut buf, None);
        assert_eq!(buf, vec![ATYP_EMPTY]);
        let (got, used) = decode_addr_port(&buf).unwrap();
        assert_eq!((got.is_none(), used), (true, 1));
    }

    #[test]
    fn addr_known_bytes() {
        let mut buf = Vec::new();
        encode_addr_port(&mut buf, Some(&NetAddr::domain("example.com", 443).unwrap()));
        assert_eq!(
            buf,
            vec![
                0x00, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
                0x01, 0xbb
            ]
        );
        let mut buf = Vec::new();
        encode_addr_port(
            &mut buf,
            Some(&NetAddr::new(Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 80)),
        );
        assert_eq!(buf, vec![0x01, 127, 0, 0, 1, 0x00, 0x50]);
        // Truncated and invalid forms are rejected.
        for cut in 0..buf.len() {
            assert!(decode_addr_port(&buf[..cut]).is_err(), "cut {cut}");
        }
        assert!(decode_addr_port(&[0x03, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn connect_frame_layout() {
        let target = NetAddr::domain("example.com", 443).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&[VERSION, CMD_CONNECT]);
        encode_addr_port(&mut frame, Some(&target));
        assert_eq!(&frame[..2], &[0x05, 0x01]);
        let (addr, used) = decode_addr_port(&frame[2..]).unwrap();
        assert_eq!(addr.as_ref(), Some(&target));
        assert_eq!(used, frame.len() - 2);
    }

    #[test]
    fn authenticate_frame_layout() {
        let uuid = uuid::Uuid::parse_str("d342d11e-d424-4583-a362-9491582acbd7").unwrap();
        let token = [0x42u8; AUTH_TOKEN_LEN];
        let frame = build_authenticate_frame(uuid, &token);
        assert_eq!(frame.len(), AUTHENTICATE_LEN);
        assert_eq!(frame[0], VERSION);
        assert_eq!(frame[1], CMD_AUTHENTICATE);
        assert_eq!(&frame[2..18], uuid.as_bytes());
        assert_eq!(&frame[18..], &token);
        // Hyphenated config form maps to the raw 16 wire bytes.
        assert_eq!(uuid.as_bytes()[0], 0xd3);
        assert_eq!(uuid.as_bytes()[15], 0xd7);
    }

    #[test]
    fn packet_frame_roundtrip() {
        let target = NetAddr::domain("example.com", 53).unwrap();
        let frame = encode_packet_frame(9, 513, 0, 1, Some(&target), b"query");
        let f = decode_packet_frame(&frame).unwrap();
        assert_eq!((f.session_id, f.packet_id, f.frag_id, f.frag_total), (9, 513, 0, 1));
        assert_eq!(f.addr.as_ref(), Some(&target));
        assert_eq!(f.data, b"query");
        // Header layout: ver, cmd, sid u16be, pid u16be, total, id, len
        // u16be, then the address.
        assert_eq!(
            &frame[..10],
            &[0x05, 0x02, 0x00, 0x09, 0x02, 0x01, 0x01, 0x00, 0x00, 0x05]
        );
        for cut in 0..frame.len() {
            assert!(decode_packet_frame(&frame[..cut]).is_err(), "cut {cut}");
        }
        // Non-packet commands are rejected.
        let mut bogus = encode_packet_frame(1, 1, 0, 1, Some(&target), b"x");
        bogus[1] = CMD_HEARTBEAT;
        assert!(decode_packet_frame(&bogus).is_err());
    }

    #[test]
    fn heartbeat_and_dissociate_frames() {
        assert_eq!(heartbeat_frame(), [0x05, 0x04]);
        let sid: u16 = 0x0102;
        let frame = [VERSION, CMD_DISSOCIATE, (sid >> 8) as u8, sid as u8];
        assert_eq!(frame, [0x05, 0x03, 0x01, 0x02]);
    }

    #[test]
    fn fragmentation_fits_mtu_and_reassembles() {
        let target = NetAddr::domain("example.com", 53).unwrap();
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let frames = fragment_packet(3, 77, &target, &data);
        assert!(frames.len() > 1);
        let mut reassembled = Vec::new();
        for (i, frame) in frames.iter().enumerate() {
            assert!(frame.len() <= UDP_MTU, "frame {i} is {}", frame.len());
            let f = decode_packet_frame(frame).unwrap();
            assert_eq!((f.session_id, f.packet_id), (3, 77));
            assert_eq!(f.frag_id as usize, i);
            assert_eq!(f.frag_total as usize, frames.len());
            if i == 0 {
                assert_eq!(f.addr.as_ref(), Some(&target));
            } else {
                // Later fragments carry the empty address.
                assert_eq!(f.addr, None);
            }
            reassembled.extend_from_slice(f.data);
        }
        assert_eq!(reassembled, data);
        // Small payloads stay whole.
        let one = fragment_packet(3, 78, &target, b"tiny");
        assert_eq!(one.len(), 1);
        let f = decode_packet_frame(&one[0]).unwrap();
        assert_eq!((f.frag_id, f.frag_total, f.addr.as_ref(), f.data), (0, 1, Some(&target), &b"tiny"[..]));
    }

    // ---------------------------------------------------- ECH over QUIC

    /// `connect_ech`: the dial rides the engine's own TLS 1.3 stack with
    /// the ECH cover (inner SNI/ALPN `tuic`), an ECH-terminating quinn
    /// server accepts, and the Authenticate token — an RFC 8446 §7.5
    /// exporter over the ECH handshake — verifies server-side. Then a
    /// TCP relay stream echoes.
    #[tokio::test]
    async fn ech_connect_authenticates_and_relays() {
        let (sk_r, list) = crate::quic::tls13::test_server::ech_server_key(
            &[11u8; 32],
            0x55,
            b"tuic-public.example",
        );
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::EchAccept {
                sk_r,
                config_list: list.clone(),
            },
        )
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();

        let uuid = uuid::Uuid::new_v4();
        let password = format!("pass-{:016x}", rand::random::<u64>());
        let seen_uuid = uuid;
        let seen_password = password.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let seen_uuid = seen_uuid;
                let seen_password = seen_password.clone();
                tokio::spawn(async move {
                    // Authenticate: one uni stream, VER||TYPE||UUID||TOKEN.
                    if let Ok(mut uni) = conn.accept_uni().await {
                        let mut head = [0u8; 2 + 16 + 32];
                        if uni.read_exact(&mut head).await.is_ok() {
                            assert_eq!(&head[..2], &[VERSION, CMD_AUTHENTICATE]);
                            assert_eq!(&head[2..18], seen_uuid.as_bytes());
                            let mut expect = [0u8; 32];
                            conn.export_keying_material(
                                &mut expect,
                                seen_uuid.as_bytes(),
                                seen_password.as_bytes(),
                            )
                            .unwrap();
                            assert_eq!(&head[18..50], &expect, "exporter token mismatch");
                        }
                    }
                    // Echo every bi stream (the relay); keep the
                    // connection handle alive — dropping it would close
                    // the connection under the client.
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            while let Ok(Some(n)) = recv.read(&mut buf).await {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            let _ = send.finish();
                        });
                    }
                });
            }
        });

        let cfg = TuicCfg {
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            uuid,
            password,
            sni: "tuic-inner.example".to_string(),
            skip_verify: true,
            udp_relay_mode: UdpRelayMode::Native,
        };
        use base64::Engine as _;
        let opts = crate::proto::ech::EchOptions {
            enable: true,
            config: base64::engine::general_purpose::STANDARD.encode(&list),
            query_server_name: String::new(),
        };

        let conn = crate::proto::tuic::connect_ech(&cfg, &opts)
            .await
            .expect("ech dial + authenticate");
        // ALPN negotiated through the ECH inner hello.
        let data = conn
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(&b"tuic"[..]));

        let target = NetAddr::domain("ech.example", 443).unwrap();
        let mut stream = crate::proto::tuic::tcp_stream(&conn, &target)
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"tuic ech relay").await.unwrap();
        // The echo returns the whole stream (command header included);
        // one bounded read must carry the payload as the tail (avoid
        // read_to_end: neither side FINs first).
        let mut echoed = [0u8; 256];
        let n = stream.read(&mut echoed).await.unwrap();
        assert!(n > 0, "no echo");
        let echoed = &echoed[..n];
        assert!(echoed.ends_with(b"tuic ech relay"), "{echoed:?}");
    }

    #[test]
    fn udp_relay_mode_parse() {
        assert_eq!(UdpRelayMode::parse("native").unwrap(), UdpRelayMode::Native);
        assert_eq!(UdpRelayMode::parse("quic").unwrap(), UdpRelayMode::Quic);
        assert_eq!(UdpRelayMode::default(), UdpRelayMode::Native);
        assert!(UdpRelayMode::parse("legacy").is_err());
    }
}
