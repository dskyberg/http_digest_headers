#![doc = include_str!("../README.md")]

//!
//! # Features
//!
//! ## Crypto Support
//! Both OpenSSL and Ring are currently supported (with openssl as the default).
//! But the crate is designed such that extending for additional crypto libs
//! should be trivial. Just send me a PR!
//!
//! - use_openssl: This is the default
//! - use_ring: Turn off default features and add `use_ring`
//! ```toml
//! [dependencies]
//! http_digest_headers = { version="0.1.0", default-features = false, features ="use_ring" }
//!```
//!
//! # Examples
//! ## Generate a digest header value
//!
//! ```rust
//! use http_digest_headers::{DigestHeader, DigestMethod, Error};
//!
//! fn make_digest_header() -> Result<String, Error> {
//!    // Generate some simple test data.  This can be anything.
//!    let data = b"this is some data";
//!
//!    // Create a builder, and digest with both SHA-256 and SHA-512.
//!    let builder = DigestHeader::new()
//!    .with_method(DigestMethod::SHA256, data)?
//!    .with_method(DigestMethod::SHA512, data)?;
//!
//!    // Generate the resulting strings for the digest header value.
//!    let header_value = format!("{}", builder);
//!
//!    // The result:String can now be used in a digest header.  For instance,
//!    // for reqwest, you might use client.header("digest", result).
//!    Ok(header_value)
//! }
//!
//! ```
use std::str::FromStr;
use std::fmt::{Display, Formatter};

use anyhow::Result;
use base64;
use thiserror::Error;

#[cfg(feature = "use_openssl")]
use openssl::hash::{hash, MessageDigest};

#[cfg(feature = "use_ring")]
use ring;

/// Standard Error values.  Errors are developed with [thiserror].
#[derive(Error, Debug)]
pub enum Error {
    /// Represents a failure to parse a PEM file
    #[cfg(feature = "use_openssl")]
    #[error("Digest failed")]
    DigestError(#[from] openssl::error::ErrorStack),

    #[error("Badly formed digest")]
    ParseDigestError,

    #[error("Unknown Digest method")]
    ParseDigestMethod,

    #[error("Base64 decode error")]
    DecodeError(#[from] base64::DecodeError),
}

/// Digest methods supported by this crate.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DigestMethod {
    SHA256,
    IdSHA256,
    SHA512,
    IdSHA512,
}

/// Convert the digest method name to an IANA registered value
impl Display for DigestMethod {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let s = match self {
            Self::SHA256 => "sha-256".to_owned(),
            Self::IdSHA256 => "id-sha-256".to_owned(),
            Self::SHA512 => "sha-512".to_owned(),
            Self::IdSHA512 => "id-sha-512".to_owned(),
        };
        write!(f, "{}", s)
    }
}

/// Convert an IANA registered value string to a DigestMethod
impl FromStr for DigestMethod {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = match s.to_lowercase().as_ref() {
            "sha-256" => DigestMethod::SHA256,
            "id-sha-256" => DigestMethod::IdSHA256,
            "sha-512" => DigestMethod::SHA512,
            "id-sha-512" => DigestMethod::IdSHA512,
            _ => return Err(Error::ParseDigestMethod),
        };

        Ok(res)
    }
}

#[cfg(feature = "use_ring")]
trait Ring {
    fn digest(&self, data: &[u8]) -> Result<Digest>;
    fn verify(&self, data: &[u8]) -> Result<bool>;
}

#[cfg(feature = "use_ring")]
impl Ring for Digest {
    fn digest(&self, data: &[u8]) -> Result<Digest> {
        let size = match self.method {
            DigestMethod::SHA256 => &ring::digest::SHA256,
            DigestMethod::IdSHA256 => &ring::digest::SHA256,
            DigestMethod::SHA512 => &ring::digest::SHA512,
            DigestMethod::IdSHA512 => &ring::digest::SHA512,
        };

        let digest = ring::digest::digest(size, data);
        Ok(Digest {
            method: self.method,
            digest: digest.as_ref().to_owned(),
        })
    }

    fn verify(&self, _data: &[u8]) -> Result<bool> {
        let digest = self.digest(data)?;
        Ok(digest == *self)
    }
}

#[cfg(feature = "use_openssl")]
trait OpenSsl {
    fn digest(&self, data: &[u8]) -> Result<Digest>;
    fn verify(&self, data: &[u8]) -> Result<bool>;
}

#[cfg(feature = "use_openssl")]
impl OpenSsl for Digest {
    fn digest(&self, data: &[u8]) -> Result<Digest> {
        let digester = match self.method {
            DigestMethod::SHA256 => MessageDigest::sha256(),
            DigestMethod::IdSHA256 => MessageDigest::sha256(),
            DigestMethod::SHA512 => MessageDigest::sha512(),
            DigestMethod::IdSHA512 => MessageDigest::sha512(),
        };
        let digest = hash(digester, data).map_err(|e| Error::DigestError(e))?;
        Ok(Digest {
            method: self.method,
            digest: digest.to_vec(),
        })
    }

    fn verify(&self, data: &[u8]) -> Result<bool> {
        let digest = self.digest(data)?;
        Ok(digest == *self)
    }
}

/// Encapsulates the cryptographic methods
///
/// Each crypto trait (based on features such as use_openssl) defines a
/// `fn digest(&self, data: [u8]) -> Result<Digest>` method for `Digest`.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    /// Abstraction for supported digest methods
    method: DigestMethod,
    /// Resulting digest bytes
    digest: Vec<u8>,
}

impl Default for Digest {
    /// Defaults to SHA256
    fn default() -> Self {
        Self {
            method: DigestMethod::SHA256,
            digest: Vec::new(),
        }
    }
}

impl Digest {
    /// Create a `Digest` instance with a specific [DigestMethod]
    pub fn new(method: DigestMethod) -> Self {
        Self {
            method: method,
            digest: Vec::<u8>::new(),
        }
    }
}

impl ToString for Digest {
    /// Generates a string in the form of `<IANA digest alg>=<Base64 encoded digest>`
    fn to_string(&self) -> String {
        format!(
            "{}={}",
            self.method.to_string(),
            base64::encode_config(&self.digest, base64::URL_SAFE)
        )
    }
}

/// Establishes a Digest instance from a string in the form of
/// `<IANA digest alg>=<Base64 encoded digest>`
impl FromStr for Digest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((method_str, b64_digest)) = s.split_once("=") {
            let method = DigestMethod::from_str(method_str.trim())?;
            let digest = base64::decode_config(b64_digest.trim(), base64::URL_SAFE)
            .map_err(|e| Error::DecodeError(e))?;
            Ok(Digest {method, digest})
        } else {
            Err(Error::ParseDigestError)
        }
    }
}

/// Helper struct to create the actual `Digest` or `Content-Digest` header value
///
/// A `Digest` header is constructed of comma delimited set of strings with the form
/// `<digest-method>=<base64 encoded digest value>`.
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestHeader {
    digests: Vec<Digest>,
}

impl DigestHeader {
    pub fn new() -> Self {
        Self {
            digests: Vec::<Digest>::new(),
        }
    }
    /// Adds a digest without consuming the data.
    pub fn with_method(mut self, method: DigestMethod, data: &[u8]) -> Result<Self> {
        let dh = Digest::new(method).digest(data)?;
        self.digests.push(dh);

        Ok(self)
    }

    /// Verify the digests in the header
    ///
    /// This method makes no attempt to canonicalize the data provided.
    pub fn verify(&self, data: &[u8]) -> Result<bool> {
        for digest in &self.digests {
            if digest.verify(data)? == false {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Display for DigestHeader {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let strings: Vec<String> = self.digests.iter().map(|dh| dh.to_string()).collect();
        write!(f, "{}", strings.join(", "))
    }
}

impl FromStr for DigestHeader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut digests = Vec::<Digest>::new();
        let splits = s.split(",");
        for s in splits {
            let digest = Digest::from_str(s)?;
            digests.push(digest);
        }
        Ok(DigestHeader{digests})
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::{DigestHeader, DigestMethod, Digest};

    const SHA256: &str = "sha-256=3_kAh-KpXxwJPPQOe-bvTpmOIbTqONC0lOov2yV2_P4=";
    const SHA512: &str = "sha-512=ds73LiSli5AzG8mjHpQAwDVtIQG24wUf5h8exMWC1tfH9pUonY9KQSiMSvii0B1nd7ur1RkGUI5RMs3026vVZw==";

    // Generate some simple test data.  This can be anything.
    const TEST_DATA: &[u8] = b"this is some data";

    #[test]
    fn digest_method_from_str() {
        let d1 = DigestMethod::SHA256;
        let d2 = DigestMethod::from_str("sha-256").expect("failed");
        assert_eq!(d1, d2);
    }

    #[cfg(any(feature = "use_openssl", feature = "use_ring"))]
    #[test]
    fn test_digest() {
        use super::OpenSsl;
        let d1 = Digest::default();
        let d = d1.digest(TEST_DATA).expect("Failed to digest");
        let result = d.verify(TEST_DATA).expect("Failed to verify");
        assert!(result);
    }


    #[test]
    fn digest_from_str() {
        let _digest = Digest::from_str(SHA256).expect("Failed to parse Digest");
        assert!(true);
    }

    #[cfg(any(feature = "use_openssl", feature = "use_ring"))]
    #[test]
    fn digest_with_two_methods() {
        let test_value = format!("{}, {}", SHA256, SHA512);

        // Create a builder, and digest with both SHA-256 and SHA-512.
        let builder = DigestHeader::new()
            .with_method(DigestMethod::SHA256, TEST_DATA)
            .expect("digesting failed")
            .with_method(DigestMethod::SHA512, TEST_DATA)
            .expect("digesting failed");

        // Generate the resulting strings for the digest header value. For
        // reqwest, you might use client.header("digest", result) to create the header.
        let result = format!("{}", &builder);

        assert_eq!(result, test_value);
    }

    #[test]
    fn header_from_string() {
        let test_value = format!("{}, {}", SHA256, SHA512);

        let builder = DigestHeader::from_str(&test_value)
        .expect("Failed to build from string");
        let result = format!("{}", &builder);

        assert_eq!(result, test_value);
    }

    #[test]
    fn verify_header() {
        let test_value = format!("{}, {}", SHA256, SHA512);

        let header = DigestHeader::from_str(&test_value)
        .expect("Failed to build from string");
        let result = header.verify(TEST_DATA).expect("Failed to verify");

        assert!(result);
    }

}
