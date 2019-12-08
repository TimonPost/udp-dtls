use std::io::{Error, Read, Result, Write, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::result;

/// Wrapper to read from and sent data to an remote UDP endpoint.
#[derive(Debug)]
pub struct UdpChannel {
    pub socket: UdpSocket,
    pub remote_addr: Option<SocketAddr>,
}

impl Read for UdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.socket.recv(buf)
    }
}

impl Write for UdpChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if let Some(addr) = self.remote_addr {
            self.socket.send_to(buf, addr)
        }else {
            Err(Error::new(ErrorKind::Other, "aaaa"))
        }
    }

    fn flush(&mut self) -> result::Result<(), Error> {
        Ok(())
    }
}
