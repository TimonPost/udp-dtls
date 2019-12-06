use crate::{Certificate, Error};
use openssl::pkcs12::{ParsedPkcs12, Pkcs12};

/// A cryptographic identity.
///
/// An identity is an X509 certificate along with its corresponding private key and chain of certificates to a trusted
/// root.
pub struct Identity(ParsedPkcs12);

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that should be sent to clients to allow them to build a chain to a trusted
    /// root. The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    pub fn from_pkcs12(buf: &[u8], pass: &str) -> Result<Identity, Error> {
        let pkcs12 = Pkcs12::from_der(buf)?;
        let parsed = pkcs12.parse(pass)?;
        Ok(Identity(parsed))
    }

    /// Returns the X509 certificate from this identity.
    pub fn certificate(&self) -> Certificate {
        Certificate::from(self.0.cert.clone())
    }
}

impl From<ParsedPkcs12> for Identity {
    fn from(pkcs_12: ParsedPkcs12) -> Self {
        Identity(pkcs_12)
    }
}

impl AsRef<ParsedPkcs12> for Identity {
    fn as_ref(&self) -> &ParsedPkcs12 {
        &self.0
    }
}
