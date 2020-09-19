use std::{pin::Pin, task::{Context, Poll}, io, fmt};
use openssl::ssl::{SslRef};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_openssl::SslStream as AsyncSslStream;

use crate::{DtlsStream, DtlsStreamExt}; 

pub type AsyncDtlsStream<S> = DtlsStream<AsyncSslStream<S>>;

impl<S: fmt::Debug> fmt::Debug for DtlsStream<AsyncSslStream<S>> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}
 
impl<S> DtlsStreamExt<S> for AsyncDtlsStream<S> {
    fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncDtlsStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncDtlsStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: io::Read + io::Write> AsRef<AsyncSslStream<S>> for AsyncDtlsStream<S> {
    fn as_ref(&self) -> &AsyncSslStream<S> {
        &self.0
    }
}

impl<S: AsyncRead + AsyncWrite> From<AsyncSslStream<S>> for AsyncDtlsStream<S> {
    fn from(stream: AsyncSslStream<S>) -> Self {
        DtlsStream(stream)
    }
}

