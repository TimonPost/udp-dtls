use crate::{
    openssl::{init_trust, try_set_supported_protocols},
    DtlsConnectorBuilder, DtlsStream, Error, HandshakeError, Protocol,
};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io;

/// A builder for client-side DTLS-connections.
#[derive(Clone)]
pub struct DtlsConnector {
    connector: SslConnector,
    use_sni: bool,
    accept_invalid_hostnames: bool,
    accept_invalid_certs: bool,
}

impl DtlsConnector {
    /// Creates a new `DtlsConnector`.
    ///
    /// The `DtlsConnector` will use the settings from the given builder.
    ///
    /// The following propperties will be applied from the builder:
    /// - Sets minimal/maximal protocol version
    /// - Sets srtp profile by enabling the DTLS extension 'use_srtp'
    /// - Sets the certificate and private key
    /// - Adds the root certificates to the certificate store.
    pub fn new(builder: &DtlsConnectorBuilder) -> Result<DtlsConnector, Error> {
        init_trust();

        let mut connector = SslConnector::builder(SslMethod::dtls()).unwrap();

        if builder.srtp_profiles.len() > 0 {
            let srtp_line = builder
                .srtp_profiles
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            connector.set_tlsext_use_srtp(&srtp_line)?;
        }

        if let Some(ref identity) = builder.identity {
            connector.set_certificate(&(identity.0).cert)?;
            connector.set_private_key(&(identity.0).pkey)?;
            if let Some(ref chain) = (identity.0).chain {
                for cert in chain.iter().rev() {
                    connector.add_extra_chain_cert(cert.to_owned())?;
                }
            }
        }

        try_set_supported_protocols(builder.min_protocol, builder.max_protocol, &mut connector)?;

        for cert in &builder.root_certificates {
            if let Err(err) = connector.cert_store_mut().add_cert((cert.0).clone()) {
                debug!("add_cert error: {:?}", err);
            }
        }

        #[cfg(target_os = "android")]
        load_android_root_certs(&mut connector)?;

        Ok(DtlsConnector {
            connector: connector.build(),
            use_sni: builder.use_sni,
            accept_invalid_hostnames: builder.accept_invalid_hostnames,
            accept_invalid_certs: builder.accept_invalid_certs,
        })
    }

    /// Returns a new builder for a `DtlsConnector` from which you can create the `DtlsConnector`.
    pub fn builder() -> DtlsConnectorBuilder {
        DtlsConnectorBuilder {
            identity: None,
            srtp_profiles: vec![],
            min_protocol: Some(Protocol::Dtlsv10),
            max_protocol: None,
            root_certificates: vec![],
            use_sni: true,
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
        }
    }

    /// Initiates a DTLS handshake.
    ///
    /// The provided domain will be used for both SNI and certificate hostname
    /// validation.
    ///
    /// If the socket is nonblocking and a `WouldBlock` error is returned during
    /// the handshake, a `HandshakeError::WouldBlock` error will be returned
    /// which can be used to restart the handshake when the socket is ready
    /// again.
    ///
    /// The domain is ignored if both SNI and hostname verification are
    /// disabled.
    pub fn connect<S>(&self, domain: &str, stream: S) -> Result<DtlsStream<S>, HandshakeError<S>>
    where
        S: io::Read + io::Write,
    {
        let mut ssl = self
            .connector
            .configure()?
            .use_server_name_indication(self.use_sni)
            .verify_hostname(!self.accept_invalid_hostnames);
        if self.accept_invalid_certs {
            ssl.set_verify(SslVerifyMode::NONE);
        }

        let s = ssl.connect(domain, stream)?;
        Ok(DtlsStream(s))
    }
}
