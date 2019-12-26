use openssl::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslOptions, SslVerifyMode},
};
use std::sync::Once;

use crate::{Identity, Protocol};
use lazy_static::lazy_static;
use openssl::ssl::{Ssl, SslMethod, SslStreamBuilder, SslContext};
use rand::Rng;
use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV6};
use std::process::id;
use super::connection::ConnectionInfo;

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

use arrayvec::ArrayVec;
use openssl::{self, ex_data};
use crate::connection::{ListenKeys, CookieFactory, ConnectionId};
use rand::rngs::OsRng;

lazy_static! {
    static ref CONNECTION_INFO_INDEX: ex_data::Index<Ssl, ConnectionInfo> = Ssl::new_ex_index().unwrap();
}

const LOCAL_ID_LEN: usize = 8;
const MAX_CID_SIZE: usize = 18;
const MIN_CID_SIZE: usize = 4;

pub fn dtls_connect(identity: Identity) {
    let identity = identity.as_ref();

    let mut builder = SslContextBuilder::new(SslMethod::dtls()).expect("Context uilder");
    builder.set_cipher_list("eNULL:!MD5");
    builder.set_private_key(&identity.pkey).expect("setting private key");
    builder.set_certificate(&identity.cert).expect("setting certificate");
    builder.check_private_key().expect("private key and certificate are not valid");
    builder.set_verify_depth(2);
    builder.set_read_ahead(true);

    let context = builder.build();
    context.b
    let mut ssl = openssl::ssl::Ssl::new(&context).expect("building ssl");



}

pub fn dtls_listen<S: Read + Write>(stream: S, addr: SocketAddr, identity: Identity) -> Option<SocketAddr> {
    let mut rng = OsRng::default();
    let local_id = ConnectionId::random(&mut rng, LOCAL_ID_LEN as u8);
    let remote_id = ConnectionId::random(&mut rng, MAX_CID_SIZE as u8);
    let listen_keys = ListenKeys::new(&mut rand::thread_rng());
    let mut factory = CookieFactory::new(listen_keys.cookie);

    let mut builder = SslContextBuilder::new(SslMethod::dtls()).expect("Context uilder");

    /*
        CIPHER
    */

    let identity = identity.as_ref();

    if let Some(ref chain) = identity.chain {
        for cert in chain.iter().rev() {
            builder.add_extra_chain_cert(cert.to_owned());
        }
    }

    builder.set_cipher_list("ALL:NULL:eNULL:aNULL");

    builder.set_private_key(&identity.pkey).expect("setting private key");
    builder.set_certificate(&identity.cert).expect("setting certificate");
    builder.check_private_key().expect("private key and certificate are not valid");

    builder.set_verify(SslVerifyMode::PEER); // verify callback
    builder.set_verify_callback(SslVerifyMode::PEER, |x, _| x);

    builder.set_read_ahead(true);

    /*
          COOKIE
    */

    let factory1 = factory.clone();
    builder.set_cookie_generate_cb(move |dtls, buf| {
        let conn = dtls.ex_data(*CONNECTION_INFO_INDEX).expect("no ex data");
        Ok(factory1.generate(conn, buf))
    });

    builder.set_cookie_verify_cb(move |dtls, cookie| {
        let conn = dtls.ex_data(*CONNECTION_INFO_INDEX).expect("no ex data exists");
        factory.verify(conn, cookie)
    });

    builder.set_options(SslOptions::COOKIE_EXCHANGE);
    builder.set_session_id_context(&[0, 1, 2, 3, 4]).expect("set session id");

    try_set_supported_protocols(Some(Protocol::Dtlsv10), None, &mut builder).expect("set supported protocols");

    /*
      BUILDING
    */


    let context = builder.build();

    let mut ssl = openssl::ssl::Ssl::new(&context).expect("building ssl");

    ssl.set_ex_data(*CONNECTION_INFO_INDEX, ConnectionInfo { id: local_id.clone(), remote: addr });


    let mut stream = SslStreamBuilder::new(ssl, stream);
    stream.set_dtls_mtu_size(1500);

    return stream.dtls_listen().expect("listen");
}


