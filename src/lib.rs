//! An abstraction over OpenSSL DTLS implementations.

#[macro_use]
extern crate log;

#[cfg(test)]
mod test;

mod certificate;
mod certificate_fingerprint;
mod dtls_acceptor;
mod dtls_acceptor_builder;
mod dtls_connection_builder;
mod dtls_connector;
mod dtls_stream;
mod error;
mod idenitity;
mod midhandshake_dtls_steam;
mod openssl;
mod protocol;
mod srtp_profile;
mod udp_channel;

pub use self::certificate_fingerprint::{CertificateFingerprint, SignatureAlgorithm};
pub use self::dtls_acceptor_builder::DtlsAcceptorBuilder;
pub use self::dtls_connection_builder::DtlsConnectorBuilder;

pub use self::certificate::Certificate;
pub use self::dtls_acceptor::DtlsAcceptor;
pub use self::dtls_connector::DtlsConnector;
pub use self::dtls_stream::DtlsStream;
pub use self::error::{Error, HandshakeError, Result, SrtpProfileError};
pub use self::idenitity::Identity;
pub use self::midhandshake_dtls_steam::MidHandshakeDtlsStream;
pub use self::protocol::Protocol;
pub use self::srtp_profile::SrtpProfile;
pub use self::udp_channel::UdpChannel;
