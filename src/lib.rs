//! Crate for parsing EcPrivateKey structures as defined in [SEC1 section C4](https://www.secg.org/sec1-v2.pdf).
//! This is the default format generated by openssl for ec keys.
//!
//! ```
//! # use sec1_decode::parse_pem;
//! const PEM:&str = "-----BEGIN EC PRIVATE KEY-----
//! MHcCAQEEIASgox4rXoGc6ajVAjBCsjVIjbfHd8OK3m5v34ZWVBmmoAoGCCqGSM49
//! AwEHoUQDQgAEUfXAsSR5LH4rVdHbcK1vnYcN9I/6T7u1bl1RprSZFf89aZXL+CeG
//! G21XVW8IDhjU7HAXgrO1Sqj00zQtluVBTg==
//! -----END EC PRIVATE KEY-----";
//!
//! let parsed = parse_pem(PEM.as_bytes()).unwrap();
//! ```

mod decoder;
pub mod error;

pub use decoder::parse_pem;
pub use decoder::parse_der;
pub use decoder::EcPrivateKey;
