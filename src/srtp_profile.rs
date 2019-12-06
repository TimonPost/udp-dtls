/// SRTP is the Secure Real-Time Transport Protocol.
///
/// This enum represents the supported protection profile names.
///
/// More information: https://www.openssl.org/docs/man1.1.0/man3/SSL_get_srtp_profiles.html
#[derive(Hash, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum SrtpProfile {
    /// This corresponds to `SRTP_AES128_CM_HMAC_SHA1_80` defined in [RFC5764](https://tools.ietf.org/html/rfc5764).
    Aes128CmSha180,
    /// This corresponds to `SRTP_AES128_CM_HMAC_SHA1_32` defined in [RFC5764](https://tools.ietf.org/html/rfc5764).
    Aes128CmSha132,
    /// This corresponds to the profile of the same name defined in [RFC7714](https://tools.ietf.org/html/rfc7714).
    AeadAes128Gcm,
    /// This corresponds to the profile of the same name defined in [RFC7714](https://tools.ietf.org/html/rfc7714).
    AeadAes256Gcm,
    #[doc(hidden)]
    __Nonexhaustive,
}

impl ToString for SrtpProfile {
    fn to_string(&self) -> String {
        match self {
            SrtpProfile::Aes128CmSha180 => "SRTP_AES128_CM_SHA1_80",
            SrtpProfile::Aes128CmSha132 => "SRTP_AES128_CM_SHA1_32",
            SrtpProfile::AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM",
            SrtpProfile::AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM",
            SrtpProfile::__Nonexhaustive => unreachable!(),
        }
        .to_string()
    }
}
