use crate::{CertificateFingerprint, Error, SignatureAlgorithm};
use openssl::{hash::MessageDigest, x509::X509};

/// A wrapper type for an `X509` certificate.
#[derive(Clone)]
pub struct Certificate(pub X509);

impl Certificate {
    /// Deserializes a DER-encoded X509 structure.
    ///
    /// # Underlying SSL
    /// This corresponds to [`d2i_X509`].
    ///
    /// [`d2i_X509`]: https://www.openssl.org/docs/manmaster/man3/d2i_X509.html
    pub fn from_der(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_der(buf)?;
        Ok(Certificate(cert))
    }

    /// Deserializes a PEM-encoded X509 structure.
    ///
    /// The input should have a header of `-----BEGIN CERTIFICATE-----`.
    ///
    /// # Underlying SSL
    /// This corresponds to [`PEM_read_bio_X509`].
    ///
    /// [`PEM_read_bio_X509`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_X509.html
    pub fn from_pem(buf: &[u8]) -> Result<Certificate, Error> {
        let cert = X509::from_pem(buf)?;
        Ok(Certificate(cert))
    }

    /// Serializes the certificate into a DER-encoded X509 structure.
    ///
    /// # Underlying SSL
    /// This corresponds to [`i2d_X509`].
    ///
    /// [`i2d_X509`]: https://www.openssl.org/docs/man1.1.0/crypto/i2d_X509.html
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = self.0.to_der()?;
        Ok(der)
    }

    /// Returns the digest of the DER representation of the certificate and the cryptographic hash function used to calculate those bytes.
    ///
    /// # Underlying SSL
    /// The `bytes` are a digest of the DER representation of the certificate.
    ///
    /// The bytes are calculated by the [`X509_digest`] function.
    ///
    /// [`X509_digest`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_digest.html
    pub fn fingerprint(
        &self,
        signature_algorithm: SignatureAlgorithm,
    ) -> Result<CertificateFingerprint, Error> {
        let md = match signature_algorithm {
            SignatureAlgorithm::Sha1 => MessageDigest::sha1(),
            SignatureAlgorithm::Sha256 => MessageDigest::sha256(),
            // there is a whole bunch more
        };

        let digest = self.0.digest(md)?;

        Ok(CertificateFingerprint {
            bytes: digest.to_vec(),
            signature_algorithm,
        })
    }
}
