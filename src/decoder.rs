use der::Message;
use der::asn1::{OctetString, ContextSpecific};

#[derive(Clone, Debug, Eq, PartialEq, Message)]
pub struct EcPrivateKey<'a> {
    version: u8,
    key: OctetString<'a>,
    curve: Option<ContextSpecific<'a>>,
    public_key: Option<ContextSpecific<'a>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use der::Decodable;

    const PEM: &str = "MHcCAQEEIMwug/U2ds75hkEIeou9s0kj1ziCJETswt5S9ztJ2L5SoAoGCCqGSM49AwEHoUQDQgAEyjUeooXqyQxljKSu17126pjAEPTyYNApO6dGQl0PexMn0T7LI3qwmU9ZOko2Gn7LYp5LqgA0cX6rfDftsKVvtQ==";

    #[test]
    fn test_parse() {//TODO convert this to usable code and then test more with actual certs.
        let bytes = base64::decode(PEM).unwrap();

        let key = EcPrivateKey::from_der(&bytes).unwrap();

        println!("key: {:?}", key.key.as_bytes());
        println!("version: {:?}", key.version);
    }
}