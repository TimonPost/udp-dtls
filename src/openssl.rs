use openssl::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslOptions},
};
use std::sync::Once;

use crate::Protocol;
use openssl::ssl::{SslStreamBuilder, SslMethod};
use std::net::SocketAddr;
use std::io::{Read, Write};

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

pub fn dtls_listen<S: Read + Write,> (stream: S) -> Option<SocketAddr> {
    let mut builder = SslContextBuilder::new(SslMethod::dtls()).unwrap();
    builder.set_options(SslOptions::COOKIE_EXCHANGE);
    let context = builder.build();

    let ssl = openssl::ssl::Ssl::new(&context).unwrap();
    let mut stream = SslStreamBuilder::new(ssl, stream);

    println!("Listening...");

    return stream.dtls_listen().unwrap();
}
