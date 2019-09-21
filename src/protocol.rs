/// DTLS protocol versions.
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
    Dtlsv10,
    Dtlsv12,
    #[doc(hidden)]
    __NonExhaustive,
}
