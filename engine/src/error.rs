//! Engine error type.

/// Errors produced by the proxy engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),
    #[error("network: {0}")]
    Network(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("dns: {0}")]
    Dns(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection closed by rule")]
    Rejected,
}

impl Error {
    /// Config error constructor, for the many `map_err` chains.
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Protocol error constructor.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }

    /// Network error constructor.
    pub fn network(msg: impl Into<String>) -> Self {
        Error::Network(msg.into())
    }

    /// DNS error constructor.
    pub fn dns(msg: impl Into<String>) -> Self {
        Error::Dns(msg.into())
    }

    /// Crypto error constructor.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }
}

/// Result alias for engine operations.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_set_the_right_variant() {
        assert!(matches!(Error::config("x"), Error::Config(_)));
        assert!(matches!(Error::protocol("x"), Error::Protocol(_)));
        assert!(matches!(Error::network("x"), Error::Network(_)));
        assert!(matches!(Error::dns("x"), Error::Dns(_)));
        assert!(matches!(
            Error::from(std::io::Error::other("x")),
            Error::Io(_)
        ));
    }
}
