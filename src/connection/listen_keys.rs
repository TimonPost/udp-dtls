use rand::RngCore;
use rand::Rng;

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