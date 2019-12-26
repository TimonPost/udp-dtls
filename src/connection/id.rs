use arrayvec::ArrayVec;
use rand::Rng;
use std::fmt;

const MAX_CID_SIZE: usize = 18;

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId(ArrayVec<[u8; MAX_CID_SIZE]>);

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

//impl ::std::ops::DerefMut for ConnectionId {
//    fn deref_mut(&mut self) -> &mut [u8] { &mut self.0.as_ref() }
//}

impl ConnectionId {
    pub(crate) fn new(data: [u8; MAX_CID_SIZE], len: usize) -> Self {
        let mut x = ConnectionId(data.into());
        x.0.truncate(len);
        x
    }

    pub(crate) fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
        debug_assert!(len as usize <= MAX_CID_SIZE);
        let mut v = ArrayVec::from([0; MAX_CID_SIZE]);
        rng.fill_bytes(&mut v[0..len as usize]);
        v.truncate(len as usize);
        ConnectionId(v)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}