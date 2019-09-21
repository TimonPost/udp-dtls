use crate::openssl::try_set_supported_protocols;
use crate::{DtlsAcceptorBuilder, DtlsStream, HandshakeError, Identity, Protocol, Result};
use openssl::ssl::{SslAcceptor, SslMethod};
use std::{io, result};

/// A builder for `DtlsAcceptor`s.
/// A builder for server-side DTLS connections.
#[derive(Clone)]
pub struct DtlsAcceptor(pub SslAcceptor);

impl DtlsAcceptor {
    /// Creates a `DtlsAcceptor` with default settings.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn default(identity: Identity) -> Result<DtlsAcceptor> {
        DtlsAcceptor::builder(identity).build()
    }

    /// Creates a acceptor with the settings from the given builder.
    ///
    /// The `DtlsAcceptor` will use the settings from the given builder.
    ///
    /// The following properties will be applied from the builder:
    /// - Sets minimal/maximal protocol version
    /// - Sets srtp profile by enabling the DTLS extension 'use_srtp'
    /// - Sets the certificate and private key
    /// - Adds the certificates from the identity chain to the certificate chain.
    pub fn new(builder: &DtlsAcceptorBuilder) -> Result<DtlsAcceptor> {
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::dtls())?;

        if builder.srtp_profiles.len() > 0 {
            let srtp_line = builder
                .srtp_profiles
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");

            acceptor.set_tlsext_use_srtp(&srtp_line)?;
        }

        acceptor.set_private_key(&(builder.identity.0).pkey)?;
        acceptor.set_certificate(&(builder.identity.0).cert)?;

        if let Some(ref chain) = (builder.identity.0).chain {
            for cert in chain.iter().rev() {
                acceptor.add_extra_chain_cert(cert.to_owned())?;
            }
        }

        try_set_supported_protocols(builder.min_protocol, builder.max_protocol, &mut acceptor)?;

        Ok(DtlsAcceptor(acceptor.build()))
    }

    /// Returns a new builder for a `DtlsAcceptor`.
    ///
    /// The identity acts as the server's private key/certificate chain.
    pub fn builder(identity: Identity) -> DtlsAcceptorBuilder {
        DtlsAcceptorBuilder {
            identity,
            srtp_profiles: vec![],
            min_protocol: Some(Protocol::Dtlsv10),
            max_protocol: None,
        }
    }

    /// Accepts a new client connection with the provided stream.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    pub fn accept<S>(&self, stream: S) -> result::Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let s = self.0.accept(stream)?;
        Ok(DtlsStream(s))
    }
}
