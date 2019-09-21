use openssl::{
    error::ErrorStack,
    ssl::{SslContextBuilder, SslOptions},
};
use std::sync::{Once, ONCE_INIT};

use crate::Protocol;

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
    static ONCE: Once = ONCE_INIT;
    ONCE.call_once(|| openssl_probe::init_ssl_cert_env_vars());
}
