use core::fmt::Write;

#[derive(Clone, Copy, Debug)]
pub enum SignatureAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Clone, Debug)]
pub struct CertificateFingerprint {
    pub bytes: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,
}

impl ToString for CertificateFingerprint {
    fn to_string(&self) -> String {
        let mut s = match self.signature_algorithm {
            SignatureAlgorithm::Sha1 => "sha-1 ",
            SignatureAlgorithm::Sha256 => "sha-256 ",
        }
        .to_string();

        for b in &self.bytes {
            s.write_fmt(format_args!("{:02X}:", b)).unwrap();
        }

        if s.len() > 0 {
            s.pop(); //remove last ':'
        }

        s
    }
}

impl CertificateFingerprint {
    pub fn new(bytes: Vec<u8>, signature_algorithm: SignatureAlgorithm) -> CertificateFingerprint {
        CertificateFingerprint {
            bytes,
            signature_algorithm,
        }
    }
}
