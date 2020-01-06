use crate::connection::ConnectionInfo;
use blake2::{Blake2b, Digest};
use digest::{Input, VariableOutput};
use bytes::{BigEndian, ByteOrder};
use constant_time_eq::constant_time_eq;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

#[derive(Clone)]
pub struct CookieFactory {
    mac_key: [u8; 64],
}

const COOKIE_MAC_BYTES: usize = 64;

impl CookieFactory {
    pub(crate) fn new(mac_key: [u8; 64]) -> Self {
        Self { mac_key }
    }

    pub(crate) fn generate(&self, conn: &ConnectionInfo, out: &mut [u8]) -> usize {
        println!("Generating client cookie ...");
        let mac = self.generate_mac(conn);
        out[0..COOKIE_MAC_BYTES].copy_from_slice(&mac);
        COOKIE_MAC_BYTES
    }

    pub(crate) fn generate_mac(&self, conn: &ConnectionInfo) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);

        match conn.remote.ip() {
            IpAddr::V4(addr) => {
                mac.process(&addr.octets());
            },
            IpAddr::V6(addr) => {
                mac.process(&addr.octets());
            },
        }

        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }



    pub(crate) fn verify(&self, conn: &ConnectionInfo, cookie_data: &[u8]) -> bool {
        println!("Verifying client cookie ...");
        let expected = self.generate_mac(conn);

        // TODO: remove to_vec
        if cookie_data.to_vec() == expected.to_vec() {
            println!("Client cookie verified");
            return false;
        }
        println!("Client cookie not verified");
        true
    }
}