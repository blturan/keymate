//! Reading the non-secret parts of OpenSSH security-key (`-sk`) key files.
//!
//! An `-sk` private key file holds no private key material: the secret stays
//! on the security key. It records the FIDO application, flags, and the key
//! handle (the credential id), which lets Keymate ask a connected key whether
//! a file belongs to it. Only unencrypted files can be read; Keymate creates
//! its files without a passphrase.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const MAGIC: &[u8] = b"openssh-key-v1\0";
const ED25519_SK: &str = "sk-ssh-ed25519@openssh.com";
const ECDSA_SK: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
const FLAG_USER_VERIFICATION: u8 = 0x04;
const FLAG_RESIDENT: u8 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkKey {
    pub key_type: String,
    /// FIDO relying party id, e.g. `ssh:keymate-github`.
    pub application: String,
    pub flags: u8,
    /// The FIDO credential id.
    pub key_handle: Vec<u8>,
}

impl SkKey {
    pub fn resident(&self) -> bool {
        self.flags & FLAG_RESIDENT != 0
    }

    /// Created with `verify-required`: each use needs the PIN.
    pub fn verify_required(&self) -> bool {
        self.flags & FLAG_USER_VERIFICATION != 0
    }

    pub(crate) fn key_handle_base64(&self) -> String {
        STANDARD.encode(&self.key_handle)
    }
}

/// Parse an unencrypted OpenSSH private key file holding one `-sk` key.
pub(crate) fn parse_private(text: &str) -> Option<SkKey> {
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let data = STANDARD.decode(body.trim()).ok()?;
    let mut r = Reader(data.strip_prefix(MAGIC)?);

    let cipher = r.string()?;
    let _kdf = r.string()?;
    let _kdf_options = r.string()?;
    if cipher != b"none" || r.u32()? != 1 {
        return None;
    }
    let _public = r.string()?;
    let mut private = Reader(r.string()?);
    if private.u32()? != private.u32()? {
        return None;
    }

    let key_type = String::from_utf8(private.string()?.to_vec()).ok()?;
    match key_type.as_str() {
        ED25519_SK => {
            private.string()?;
        }
        ECDSA_SK => {
            private.string()?;
            private.string()?;
        }
        _ => return None,
    }
    let application = String::from_utf8(private.string()?.to_vec()).ok()?;
    let flags = private.byte()?;
    let key_handle = private.string()?.to_vec();
    Some(SkKey {
        key_type,
        application,
        flags,
        key_handle,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn put_string(out: &mut Vec<u8>, data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// Build a key file the way `ssh-keygen -t ed25519-sk -N ""` lays it out.
    pub(crate) fn key_file(application: &str, flags: u8, key_handle: &[u8]) -> String {
        let mut private = Vec::new();
        private.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 7]);
        put_string(&mut private, ED25519_SK.as_bytes());
        put_string(&mut private, &[1; 32]);
        put_string(&mut private, application.as_bytes());
        private.push(flags);
        put_string(&mut private, key_handle);
        put_string(&mut private, b"");
        put_string(&mut private, b"keymate-github@mac");
        let mut pad = 1;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }

        let mut data = MAGIC.to_vec();
        put_string(&mut data, b"none");
        put_string(&mut data, b"none");
        put_string(&mut data, b"");
        data.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut data, b"public blob");
        put_string(&mut data, &private);
        format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            STANDARD.encode(data)
        )
    }

    #[test]
    fn reads_application_flags_and_handle() {
        let key = parse_private(&key_file("ssh:keymate-github", 0x25, b"handle")).unwrap();
        assert_eq!(key.key_type, ED25519_SK);
        assert_eq!(key.application, "ssh:keymate-github");
        assert!(key.resident());
        assert!(key.verify_required());
        assert_eq!(key.key_handle, b"handle");
        assert_eq!(key.key_handle_base64(), "aGFuZGxl");

        let plain = parse_private(&key_file("ssh:", 0x01, b"h")).unwrap();
        assert!(!plain.resident() && !plain.verify_required());
    }

    #[test]
    fn rejects_other_files() {
        assert_eq!(parse_private(""), None);
        assert_eq!(parse_private("ssh-ed25519 AAAA comment"), None);
        let file = key_file("ssh:", 1, b"h");
        let end = file.find("\n-----END").unwrap();
        let truncated = format!("{}{}", &file[..end - 12], &file[end..]);
        assert_eq!(parse_private(&truncated), None);
    }
}
