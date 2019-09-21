use crate::{Certificate, Error, SrtpProfile};
use openssl::ssl;
use std::{fmt, io};

/// A stream managing a DTLS session.
///
/// A `DtlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `DtlsStream` are decrypted from `S` and bytes written
/// to a `DtlsStream` are encrypted when passing through to `S`.
pub struct DtlsStream<S>(pub ssl::SslStream<S>);

impl<S: fmt::Debug> fmt::Debug for DtlsStream<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: io::Read + io::Write> DtlsStream<S> {
    /// Export keying material
    ///
    /// # Underlying SSL
    /// This corresponds to [`SSL_export_keying_material`].
    ///
    /// [`SSL_export_keying_material`]: https://www.openssl.org/docs/manmaster/man3/SSL_export_keying_material.html
    pub fn keying_material(&self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; len];
        self.0
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)?;
        Ok(buf)
    }

    /// Gets the SRTP profile selected by handshake.
    ///
    /// # Underlying SSL
    /// DTLS extension "use_srtp" as defined in RFC5764 has to be enabled.
    ///
    /// This corresponds to [`SSL_get_selected_srtp_profile`].
    ///
    /// [`SSL_get_selected_srtp_profile`]: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_tlsext_use_srtp.html
    pub fn selected_srtp_profile(&self) -> Result<Option<SrtpProfile>, Error> {
        match self.0.ssl().selected_srtp_profile() {
            Some(profile) => Ok(profile.name().parse()?).map(Some),
            None => Ok(None),
        }
    }

    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    /// Returns the number of bytes remaining in the currently processed TLS record.
    ///
    /// If this is greater than 0, the next call to `read` will not call down to the underlying
    /// stream.
    ///
    /// # Underlying SSL
    /// This corresponds to [`SSL_pending`].
    ///
    /// [`SSL_pending`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_pending.html
    pub fn buffered_read_size(&self) -> Result<usize, Error> {
        Ok(self.0.ssl().pending())
    }

    /// Returns the peer's certificate, if present.
    ///
    /// # Underlying SSL
    /// This corresponds to [`SSL_get_peer_certificate`].
    ///
    /// [`SSL_get_peer_certificate`]: https://www.openssl.org/docs/man1.1.0/ssl/SSL_get_peer_certificate.html
    pub fn peer_certificate(&self) -> Result<Option<Certificate>, Error> {
        Ok(self.0.ssl().peer_certificate().map(Certificate))
    }

    /// Shuts down the session.
    ///
    /// The shutdown process consists of two steps. The first step sends a close notify message to
    /// the peer, after which `ShutdownResult::Sent` is returned. The second step awaits the receipt
    /// of a close notify message from the peer, after which `ShutdownResult::Received` is returned.
    ///
    /// While the connection may be closed after the first step, it is recommended to fully shut the
    /// session down. In particular, it must be fully shut down if the connection is to be used for
    /// further communication in the future.
    ///
    /// # Underlying SSL
    /// This corresponds to [`SSL_shutdown`].
    ///
    /// [`SSL_shutdown`]: https://www.openssl.org/docs/man1.0.2/ssl/SSL_shutdown.html
    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(e
                .into_io_error()
                .unwrap_or_else(|e| io::Error::new(io::ErrorKind::Other, e))),
        }
    }
}

impl<S: io::Read + io::Write> io::Read for DtlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write> io::Write for DtlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
