use openssl::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslOptions, SslVerifyMode},
};
use std::sync::Once;

use crate::{Identity, Protocol};
use openssl::ssl::{SslMethod, SslStreamBuilder};
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV6};
use std::process::id;
use bytes::BigEndian;
use std::fmt;

/// Sets protocol version requirements for the given `SslContextBuilder`
///
/// - Clears the options used by the context
/// - Enables the min/max protocol options
pub fn try_set_supported_protocols(
    min: Option<Protocol>,
    max: Option<Protocol>,
    ctx: &mut SslContextBuilder,
) -> Result<(), ErrorStack> {
    let no_ssl_mask = SslOptions::NO_SSL_MASK;

    ctx.clear_options(no_ssl_mask);
    let mut options = SslOptions::empty();
    options |= match min {
        None | Some(Protocol::Dtlsv10) => SslOptions::empty(),
        Some(Protocol::Dtlsv12) => SslOptions::NO_DTLSV1,
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };
    options |= match max {
        None | Some(Protocol::Dtlsv12) => SslOptions::empty(),
        Some(Protocol::Dtlsv10) => SslOptions::NO_DTLSV1_2,
        Some(Protocol::__NonExhaustive) => unreachable!(),
    };

    ctx.set_options(options);

    Ok(())
}

pub fn init_trust() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| openssl_probe::init_ssl_cert_env_vars());
}

fn dtls_verify_callback(ok: i32, ctx: X509_STORE_VERIFY) -> i32 {
    return true;
}

pub fn dtls_listen<S: Read + Write>(stream: S, identity: Identity) -> Option<SocketAddr> {
    CookieFactory::new()


    let mut builder = SslContextBuilder::new(SslMethod::dtls()).unwrap();
    builder.set_options(SslOptions::COOKIE_EXCHANGE);
    builder.set_cipher_list("ALL:NULL:eNULL:aNULL");
    builder.set_session_id_context(&[0,1,2,3,4]);
    builder.set_verify_callback(SslVerifyMode::PEER, |bool, cert| {
        true;
    });
    builder.set_read_ahead(true);
    builder.set_cookie_generate_cb(||)


    let identity = identity.as_ref();

    builder.set_private_key(&identity.pkey);
    builder.set_certificate(&identity.cert);

    if let Some(ref chain) = identity.chain {
        for cert in chain.iter().rev() {
            builder.add_extra_chain_cert(cert.to_owned());
        }
    }

    try_set_supported_protocols(Some(Protocol::Dtlsv10), None, &mut builder);

    let context = builder.build();

    let ssl = openssl::ssl::Ssl::new(&context).unwrap();

    let bio = ssl.as_ref().get_raw_rbio();

    let mut stream = SslStreamBuilder::new(ssl, stream);
    stream.set_dtls_mtu_size(1500);

    println!("Listening...");

    return stream.dtls_listen().unwrap();
}

struct CookieFactory {
    mac_key: [u8; 64]
}

const COOKIE_MAC_BYTES: usize = 64;

impl CookieFactory {
    fn new(mac_key: [u8; 64]) -> Self {
        Self { mac_key }
    }

    fn generate(&self, conn: &ConnectionInfo, out: &mut [u8]) -> usize {
        let mac = self.generate_mac(conn);
        out[0..COOKIE_MAC_BYTES].copy_from_slice(&mac);
        COOKIE_MAC_BYTES
    }

    fn generate_mac(&self, conn: &ConnectionInfo) -> [u8; COOKIE_MAC_BYTES] {
        let mut mac = Blake2b::new_keyed(&self.mac_key, COOKIE_MAC_BYTES);
        mac.process(&conn.remote.ip().octets());
        {
            let mut buf = [0; 2];
            BigEndian::write_u16(&mut buf, conn.remote.port());
            mac.process(&buf);
        }
        let mut result = [0; COOKIE_MAC_BYTES];
        mac.variable_result(&mut result).unwrap();
        result
    }

    fn verify(&self, conn: &ConnectionInfo, cookie_data: &[u8]) -> bool {
        let expected = self.generate_mac(conn);
        if !constant_time_eq(cookie_data, &expected) { return false; }
        true
    }
}

struct ConnectionInfo {
    id: ConnectionId,
    remote: SocketAddrV6,
}

const MAX_CID_SIZE: usize = 18;

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId(Vec<[u8; MAX_CID_SIZE]>);

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.0 }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] { &mut self.0.as_ref() }
}

impl ConnectionId {
    pub(crate) fn new(data: [u8; MAX_CID_SIZE], len: usize) -> Self {
        let mut x = ConnectionId(data.into());
        x.0.truncate(len);
        x
    }

    fn random<R: Rng>(rng: &mut R, len: u8) -> Self {
        debug_assert!(len as usize <= MAX_CID_SIZE);
        let mut v = Vec::from([0; MAX_CID_SIZE]);
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

/// Information that should be preserved between restarts for server endpoints.
///
/// Keeping this around allows better behavior by clients that communicated with a previous instance of the same
/// endpoint.
#[derive(Copy, Clone)]
pub struct ListenKeys {
    /// Cryptographic key used to ensure integrity of data included in handshake cookies.
    ///
    /// Initialize with random bytes.
    pub cookie: [u8; 64],
    /// Cryptographic key used to send authenticated connection resets to clients who were communicating with a previous
    /// instance of tihs endpoint.
    ///
    /// Initialize with random bytes.
    pub reset: [u8; 64],
}

impl ListenKeys {
    /// Generate new keys.
    ///
    /// Be careful to use a cryptography-grade RNG.
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let mut cookie = [0; 64];
        let mut reset = [0; 64];
        rng.fill_bytes(&mut cookie);
        rng.fill_bytes(&mut reset);
        Self { cookie, reset }
    }
}
