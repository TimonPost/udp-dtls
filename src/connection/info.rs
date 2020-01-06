use crate::connection::ConnectionId;
use std::net::{SocketAddrV6, SocketAddr};

#[derive(Debug)]
pub struct ConnectionInfo {
    pub (crate) id: ConnectionId,
    pub(crate) remote: SocketAddr,
}