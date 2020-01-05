use std::pin::Pin;
use std::task::{Context, Poll};
use std::io::Result;
use tokio::net::UdpSocket as AsyncUdpSocket;
use tokio::io::{AsyncRead, AsyncWrite};
use futures::future::FutureExt;

use crate::UdpChannel;

pub type AsyncUdpChannel = UdpChannel<AsyncUdpSocket>;

impl Unpin for AsyncUdpChannel {}

impl AsyncRead for AsyncUdpChannel {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut[u8]) -> Poll<Result<usize>> {
        let mut future = Box::pin(self.socket.recv(buf));
        future.poll_unpin(cx)
    }
}

impl AsyncWrite for AsyncUdpChannel {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize>>{
        let remote_addr = self.remote_addr;
        let mut future = Box::pin(self.socket.send_to(buf, remote_addr));
        future.poll_unpin(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}
