//! Wave-8 stub: registered ahead of the port pass; replaced wholesale.
//!
//! The restls server listener: every accepted TCP conn is wrapped by the
//! server half of the restls handshake, then relayed to `dest` (the
//! camouflage target) through the engine.
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{serve_with, ServerConfig, SharedRelay};

pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<std::net::SocketAddr> {
    let _ = (&cfg, relay);
    Err(Error::config(
        "restls listener is a wave-8 stub (server handshake pending)",
    ))
}

#[allow(dead_code)]
async fn _unused(cfg: &ServerConfig) -> Result<std::net::SocketAddr> {
    serve_with(cfg, |_s, _a, _p| async { Ok(()) }).await
}
