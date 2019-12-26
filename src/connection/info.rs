use crate::connection::ConnectionId;
use std::net::{SocketAddrV6, SocketAddr};

pub struct ConnectionInfo {
    pub (crate) id: ConnectionId,
    pub(crate) remote: SocketAddr,
}