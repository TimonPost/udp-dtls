use std::io::{Error, Read, Result, Write};
use std::net::{SocketAddr, UdpSocket};
use std::result;

/// Wrapper to read from and sent data to an remote UDP endpoint.
#[derive(Debug)]
pub struct UdpChannel {
    pub socket: UdpSocket,
    pub remote_addr: SocketAddr,
}

impl Read for UdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.socket.recv(buf)
    }
}

impl Write for UdpChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.socket.send_to(buf, self.remote_addr)
    }

    fn flush(&mut self) -> result::Result<(), Error> {
        Ok(())
    }
}
