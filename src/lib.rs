use std::fmt;
use std::path::Path;

use lopdf::Document;

#[derive(Debug)]
pub enum ExtractError {
    Io(std::io::Error),
    Pdf(lopdf::Error),
    NotEncrypted,
    MissingField(&'static str),
    InvalidField(&'static str),
}

impl fmt::Display for ExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractError::Io(e) => write!(f, "I/O error: {e}"),
            ExtractError::Pdf(e) => write!(f, "PDF error: {e}"),
            ExtractError::NotEncrypted => write!(f, "File is not encrypted"),
            ExtractError::MissingField(name) => write!(f, "Missing field: {name}"),
            ExtractError::InvalidField(name) => write!(f, "Invalid field: {name}"),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        ExtractError::Io(e)
    }
}

impl From<lopdf::Error> for ExtractError {
    fn from(e: lopdf::Error) -> Self {
        ExtractError::Pdf(e)
    }
}

pub struct PdfHashExtractor {
    pub algorithm: i64,
    pub revision: i64,
    pub length: i64,
    pub permissions: i64,
    pub encrypt_metadata: bool,
    pub document_id: Vec<u8>,
    pub user_password: Vec<u8>,
    pub owner_password: Vec<u8>,
    pub owner_encryption_seed: Option<Vec<u8>>,
    pub user_encryption_seed: Option<Vec<u8>>,
}

fn max_password_length(revision: i64) -> usize {
    match revision {
        2 | 3 | 4 => 32,
        5 | 6 => 48,
        _ => 48,
    }
}

fn get_integer(dict: &lopdf::Dictionary, key: &[u8]) -> Option<i64> {
    dict.get(key).ok().and_then(|v| v.as_i64().ok())
}

fn get_bytes(dict: &lopdf::Dictionary, key: &[u8]) -> Option<Vec<u8>> {
    dict.get(key).ok().and_then(|v| match v {
        lopdf::Object::String(bytes, _) => Some(bytes.clone()),
        _ => None,
    })
}

impl PdfHashExtractor {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ExtractError> {
        let doc = Document::load(path)?;

        let encrypt_dict = doc
            .get_encrypted()
            .map_err(|_| ExtractError::NotEncrypted)?;

        let algorithm = get_integer(encrypt_dict, b"V")
            .ok_or(ExtractError::MissingField("/V"))?;
        let revision = get_integer(encrypt_dict, b"R")
            .ok_or(ExtractError::MissingField("/R"))?;
        let length = get_integer(encrypt_dict, b"Length").unwrap_or(40);
        let raw_p = get_integer(encrypt_dict, b"P")
            .ok_or(ExtractError::MissingField("/P"))?;
        let permissions = (raw_p as i32) as i64;

        let encrypt_metadata = match encrypt_dict.get(b"EncryptMetadata") {
            Ok(lopdf::Object::Boolean(b)) => *b,
            _ => true,
        };

        let document_id = doc
            .trailer
            .get(b"ID")
            .map_err(|_| ExtractError::MissingField("/ID"))?
            .as_array()
            .map_err(|_| ExtractError::InvalidField("/ID"))?
            .first()
            .ok_or(ExtractError::InvalidField("/ID"))?
            .as_str()
            .map_err(|_| ExtractError::InvalidField("/ID"))?
            .to_vec();

        let max_len = max_password_length(revision);

        let u_data = get_bytes(encrypt_dict, b"U")
            .ok_or(ExtractError::MissingField("/U"))?;
        let user_password = u_data[..max_len.min(u_data.len())].to_vec();

        let o_data = get_bytes(encrypt_dict, b"O")
            .ok_or(ExtractError::MissingField("/O"))?;
        let owner_password = o_data[..max_len.min(o_data.len())].to_vec();

        let owner_encryption_seed = get_bytes(encrypt_dict, b"OE")
            .map(|d| d[..max_len.min(d.len())].to_vec());
        let user_encryption_seed = get_bytes(encrypt_dict, b"UE")
            .map(|d| d[..max_len.min(d.len())].to_vec());

        Ok(PdfHashExtractor {
            algorithm,
            revision,
            length,
            permissions,
            encrypt_metadata,
            document_id,
            user_password,
            owner_password,
            owner_encryption_seed,
            user_encryption_seed,
        })
    }

    pub fn format_hash(&self) -> String {
        let encrypt_metadata_flag = if self.encrypt_metadata { 1 } else { 0 };
        let id_hex = hex::encode(&self.document_id);
        let u_hex = hex::encode(&self.user_password);
        let o_hex = hex::encode(&self.owner_password);

        let mut result = format!(
            "$pdf${}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
            self.algorithm,
            self.revision,
            self.length,
            self.permissions,
            encrypt_metadata_flag,
            self.document_id.len(),
            id_hex,
            self.user_password.len(),
            u_hex,
            self.owner_password.len(),
            o_hex,
        );

        if let Some(ref oe) = self.owner_encryption_seed {
            let oe_hex = hex::encode(oe);
            result.push_str(&format!("*{}*{}", oe.len(), oe_hex));
        }

        if let Some(ref ue) = self.user_encryption_seed {
            let ue_hex = hex::encode(ue);
            result.push_str(&format!("*{}*{}", ue.len(), ue_hex));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_password_length() {
        assert_eq!(max_password_length(2), 32);
        assert_eq!(max_password_length(3), 32);
        assert_eq!(max_password_length(4), 32);
        assert_eq!(max_password_length(5), 48);
        assert_eq!(max_password_length(6), 48);
        assert_eq!(max_password_length(99), 48);
    }

    #[test]
    fn test_example_pdf() {
        let extractor = PdfHashExtractor::from_file("docs/example.pdf")
            .expect("Failed to extract hash from example.pdf");
        let hash = extractor.format_hash();
        let expected = include_str!("../docs/example.txt").trim();
        assert_eq!(hash, expected);
    }
}
