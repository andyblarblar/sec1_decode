use thiserror::Error;

#[derive(Error, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Sec1PemError {
    /// No sequence headed by "EC PRIVATE KEY" in parsed bytes.
    #[error("there was no EcPrivateKey sequence in this file.")]
    NoECPrivateKey,
    /// There was an issue while parsing the key.
    #[error("There was an error while parsing the sequence.")]
    ParseError,
}
