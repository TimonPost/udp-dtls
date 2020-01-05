use std::io::{Error, Read, Result, Write};
use std::net::{SocketAddr, UdpSocket};
use std::result;

/// Wrapper to read from and sent data to an remote UDP endpoint.
#[derive(Debug)]
pub struct UdpChannel<S> {
    pub socket: S,
    pub remote_addr: SocketAddr,
}

pub type SyncUdpChannel = UdpChannel<UdpSocket>;

impl Read for SyncUdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.socket.recv(buf)
    }
}

impl Write for SyncUdpChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.socket.send_to(buf, self.remote_addr)
    }

    fn flush(&mut self) -> result::Result<(), Error> {
        Ok(())
    }
}
