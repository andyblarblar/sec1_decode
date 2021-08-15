use crate::error::Sec1PemError;
use der::asn1::{ContextSpecific, OctetString};
pub use der::{Decodable, Message};

#[derive(Clone, Debug, Eq, PartialEq, Message)]
/// Direct intermediate representation of the der sequence. This is just a view over that sequence,
/// so it cannot be simply returned from a function, even when cloned.
struct EcPrivateKey_<'a> {
    version: u8,
    key: OctetString<'a>,
    curve: Option<ContextSpecific<'a>>,
    public_key: Option<ContextSpecific<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// The SEC1 EcPrivateKey structure decoded from the PEM.
pub struct EcPrivateKey {
    pub version: u8,
    /// The private key bytes.
    pub key: Vec<u8>,
    pub curve: Option<Vec<u8>>,//TODO reasurch what these really are, then test.
    /// The private key bytes, if included.
    pub public_key: Option<Vec<u8>>,
}

impl From<EcPrivateKey_<'_>> for EcPrivateKey {
    fn from(other: EcPrivateKey_<'_>) -> Self {
        let version = other.version;
        let key = other.key.as_bytes().to_vec();
        let curve = other.curve.map(|curve| curve.value.as_bytes().to_vec()); //TODO change this to map to tags
        let public_key = other
            .public_key
            .map(|pub_k| pub_k.value.as_bytes().to_vec());

        EcPrivateKey {
            version,
            key,
            curve,
            public_key,
        }
    }
}

const PEM_EC_HEADER: &str = "EC PRIVATE KEY";
const PEM_EC_HEADER_PUB: &str = "EC PUBLIC KEY";

pub fn parse_pem(bytes: &[u8]) -> Result<EcPrivateKey, Sec1PemError> {
    let parsed = pem::parse_many(bytes);

    //Merge bytes of all relevant sequences. This is done to ignore things like curve params.
    let pk_pem: Vec<u8> = parsed
        .into_iter()
        .filter(|pem| pem.tag == PEM_EC_HEADER || pem.tag == PEM_EC_HEADER_PUB) //Include both private and public key sequences
        .fold(Vec::new(), |mut acc, item| {
            acc.push(item.contents);
            acc
        })
        .concat();

    if !pk_pem.is_empty() {
        //Parse der sequence into struct
        let key = EcPrivateKey_::from_der(&pk_pem).unwrap();//TODO handle
        Ok(key.into())
    } else {
        Err(Sec1PemError::NoECPrivateKey)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use der::Decodable;

    const PEM: &str = "MHcCAQEEIMwug/U2ds75hkEIeou9s0kj1ziCJETswt5S9ztJ2L5SoAoGCCqGSM49AwEHoUQDQgAEyjUeooXqyQxljKSu17126pjAEPTyYNApO6dGQl0PexMn0T7LI3qwmU9ZOko2Gn7LYp5LqgA0cX6rfDftsKVvtQ==";

    #[test]
    fn test_parse() { //TODO convert this to usable code and then test more with actual certs.
    }
}
