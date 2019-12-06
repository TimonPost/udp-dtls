use crate::{DtlsStream, HandshakeError};
use openssl::ssl::MidHandshakeSslStream;
use std::{fmt, io};

/// A DTLS stream which has been interrupted midway through the handshake process.
pub struct MidHandshakeDtlsStream<S>(MidHandshakeSslStream<S>);

impl<S> MidHandshakeDtlsStream<S> {
    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S> MidHandshakeDtlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug,
{
    /// Restarts the handshake process.
    ///
    /// If the handshake completes successfully then the negotiated stream is
    /// returned. If there is a problem, however, then an error is returned.
    /// Note that the error may not be fatal. For example if the underlying
    /// stream is an asynchronous one then `HandshakeError::WouldBlock` may
    /// just mean to wait for more I/O to happen later.
    ///
    ///
    /// # Underlying SSL
    ///
    /// This corresponds to [`SSL_do_handshake`].
    ///
    /// [`SSL_do_handshake`]: https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
    pub fn handshake(self) -> Result<DtlsStream<S>, HandshakeError<S>> {
        match self.0.handshake() {
            Ok(s) => Ok(DtlsStream::from(s)),
            Err(e) => Err(e.into()),
        }
    }
}

impl<S> fmt::Debug for MidHandshakeDtlsStream<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S: fmt::Debug> AsRef<MidHandshakeSslStream<S>> for MidHandshakeDtlsStream<S> {
    fn as_ref(&self) -> &MidHandshakeSslStream<S> {
        &self.0
    }
}

impl<S: fmt::Debug> From<MidHandshakeSslStream<S>> for MidHandshakeDtlsStream<S> {
    fn from(stream: MidHandshakeSslStream<S>) -> Self {
        MidHandshakeDtlsStream(stream)
    }
}
