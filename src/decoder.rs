use crate::error::Sec1PemError;
use der::asn1::{ContextSpecific, OctetString};
pub use der::{Decodable, Message};
use std::option::Option::Some;

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
    pub curve: Option<Vec<u8>>, //TODO change this to a curve tag type
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

/// Attempts to parse an EcPrivateKey sequence from the passed bytes.
/// ```
/// # use sec1_pem::parse_pem;
/// const PEM:&str = "-----BEGIN EC PRIVATE KEY-----
/// MHcCAQEEIASgox4rXoGc6ajVAjBCsjVIjbfHd8OK3m5v34ZWVBmmoAoGCCqGSM49
/// AwEHoUQDQgAEUfXAsSR5LH4rVdHbcK1vnYcN9I/6T7u1bl1RprSZFf89aZXL+CeG
/// G21XVW8IDhjU7HAXgrO1Sqj00zQtluVBTg==
/// -----END EC PRIVATE KEY-----";
///
/// let parsed = parse_pem(PEM.as_bytes()).unwrap();
/// ```
pub fn parse_pem(bytes: &[u8]) -> Result<EcPrivateKey, Sec1PemError> {
    //Parse many to account for curve params pem
    let parsed = pem::parse_many(bytes);

    let pk_pem = parsed.into_iter().find(|pem| pem.tag == PEM_EC_HEADER);

    if let Some(pk_pem) = pk_pem {
        //Parse der sequence into struct
        let key =
            EcPrivateKey_::from_der(&pk_pem.contents).map_err(|_| Sec1PemError::ParseError)?;
        Ok(key.into())
    } else {
        Err(Sec1PemError::NoECPrivateKey)
    }
}

#[cfg(test)]
mod test {
    use std::path;
    use std::path::PathBuf;

    fn get_path() -> PathBuf {
        let mut path = path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources/");
        path
    }

    #[test]
    /// Tests that more than one PEM will parse. Does not verify the keys are correct.
    fn test_pems() {
        let path = get_path();

        //Test each pem
        for file in path.read_dir().unwrap() {
            let path = file.unwrap().path();

            //Skip the bad key
            if path.ends_with("pkcs8eckey.pem") {
                continue;
            }

            let pem = std::fs::read_to_string(path).unwrap();

            let parse = crate::parse_pem(pem.as_bytes()).unwrap();

            println!("Parsed: {:?}", parse);

            assert_eq!(parse.version, 1);
            assert!(!parse.key.is_empty());
            assert_eq!(parse.key.len(), 32); //32 * 8 bytes = 256 byte key (we're using P256)
            assert!(parse.public_key.is_some());
            assert!(parse.curve.is_some());
        }
    }

    #[test]
    /// Tests that a known key parses.
    fn test_key_parses() {
        let mut path = get_path();
        path.push("private_key2.pem"); //This is the key without a curve header.
        let pem = std::fs::read_to_string(path).unwrap();
        let expected =
            hex::decode("04A0A31E2B5E819CE9A8D5023042B235488DB7C777C38ADE6E6FDF86565419A6") //The key in hex form, dumped from openssl
                .unwrap();

        let parsed = crate::parse_pem(pem.as_bytes()).unwrap();

        assert_eq!(expected, parsed.key)
    }

    #[test]
    /// Tests that non ECPrivateKeys are not accepted.
    fn test_pkcs8_fails() {
        let mut path = get_path();
        path.push("pkcs8eckey.pem"); //pkcs8 encrypted key.
        let pem = std::fs::read_to_string(path).unwrap();

        let fails = crate::parse_pem(pem.as_bytes());

        assert_eq!(
            fails.unwrap_err(),
            crate::error::Sec1PemError::NoECPrivateKey
        )
    }
}
