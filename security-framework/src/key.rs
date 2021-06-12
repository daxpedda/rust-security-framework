//! Encryption key support

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
mod builder;

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use crate::item::KeyClass;
use crate::item::KeyType;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub use builder::{
    SecKeyAccessControl, SecKeyBiometry, SecKeyBuilder, SecKeyBuilderType, SecKeyConstraints,
    SecKeyProtection,
};
use core_foundation::base::TCFType;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::base::ToVoid;
use core_foundation::boolean::CFBoolean;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::data::CFData;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::dictionary::CFDictionary;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::error::{CFError, CFErrorRef};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::number::CFNumber;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use core_foundation::string::CFString;
use security_framework_sys::base::SecKeyRef;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::item::{
    kSecAttrApplicationTag, kSecAttrIsExtractable, kSecAttrIsPermanent, kSecAttrKeyClass,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrLabel, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecKeyKeyExchangeParameterRequestedSize,
};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
use security_framework_sys::key::{
    kSecKeyOperationTypeDecrypt, kSecKeyOperationTypeEncrypt, kSecKeyOperationTypeKeyExchange,
    kSecKeyOperationTypeSign, kSecKeyOperationTypeVerify, SecKeyCopyAttributes,
    SecKeyCopyExternalRepresentation, SecKeyCopyKeyExchangeResult, SecKeyCopyPublicKey,
    SecKeyCreateDecryptedData, SecKeyCreateEncryptedData, SecKeyCreateSignature,
    SecKeyCreateWithData, SecKeyIsAlgorithmSupported, SecKeyVerifySignature,
};
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub use security_framework_sys::key::{Algorithm, SecKeyOperationType};
use security_framework_sys::key::{SecKeyGetBlockSize, SecKeyGetTypeID};
#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
use security_framework_sys::keychain_item::kSecUseDataProtectionKeychain;
use std::fmt;

declare_TCFType! {
    /// A type representing an encryption key.
    SecKey, SecKeyRef
}
impl_TCFType!(SecKey, SecKeyRef, SecKeyGetTypeID);

unsafe impl Sync for SecKey {}
unsafe impl Send for SecKey {}

impl SecKey {
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCopyAttributes
    pub fn attributes(&self) -> CFDictionary {
        let pka = unsafe { SecKeyCopyAttributes(self.to_void() as _) };
        unsafe { CFDictionary::wrap_under_create_rule(pka) }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateRandom
    pub fn create(r#type: KeyType, size: usize) -> SecKeyBuilder {
        SecKeyBuilder::new(r#type, size)
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCopyPublicKey
    pub fn public_key(&self) -> Option<Self> {
        let key = unsafe { SecKeyCopyPublicKey(self.to_void() as _) };
        if key.is_null() {
            None
        } else {
            Some(unsafe { Self::wrap_under_create_rule(key) })
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    #[deprecated = "use `export`"]
    /// Translates to SecKeyCopyExternalRepresentation
    pub fn external_representation(&self) -> Option<CFData> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();
        let data = unsafe { SecKeyCopyExternalRepresentation(self.to_void() as _, &mut error) };
        if data.is_null() {
            return None;
        }
        Some(unsafe { CFData::wrap_under_create_rule(data) })
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Export key.
    ///
    /// Data representation depends on key type:
    /// - RSA: PKCS#1
    /// - EC: ANSI X9.63
    ///
    /// For more details see <https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation>.
    pub fn export(&self) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = ::std::ptr::null_mut();

        let data = unsafe { SecKeyCopyExternalRepresentation(self.to_void() as _, &mut error) };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            let data = unsafe { CFData::wrap_under_create_rule(data) };
            Ok(data.to_vec())
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Import key.
    ///
    /// For more details on how data should be formatted see [`SecKey::export()`].
    pub fn import(
        key_type: KeyType,
        key_class: KeyClass,
        key_size: usize,
        data: impl AsRef<[u8]>,
    ) -> Result<Self, CFError> {
        unsafe {
            let key_type = (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                key_type.to_str().as_CFType(),
            );
            let key_class = (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                key_class.to_value(),
            );
            let key_size = (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(key_size as i64).as_CFType(),
            );
            let attributes = CFDictionary::from_CFType_pairs(&[key_type, key_class, key_size]);

            let mut error: CFErrorRef = std::ptr::null_mut();

            let key = SecKeyCreateWithData(
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            );
            if !error.is_null() {
                Err(CFError::wrap_under_create_rule(error))
            } else {
                Ok(Self::wrap_under_create_rule(key))
            }
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Creates the cryptographic signature for a block of data using a private
    /// key and specified algorithm.
    pub fn create_signature(
        &self,
        algorithm: Algorithm,
        input: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateSignature(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                CFData::from_buffer(input.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Verifies the cryptographic signature for a block of data using a public
    /// key and specified algorithm.
    pub fn verify_signature(
        &self,
        algorithm: Algorithm,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<bool, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyVerifySignature(
                self.as_concrete_TypeRef(),
                algorithm.into(),
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                CFData::from_buffer(signature.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            Ok(output == 1)
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateEncryptedData
    pub fn create_encrypted(
        &self,
        algorithm: Algorithm,
        data: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateEncryptedData(
                self.to_void() as _,
                algorithm.into(),
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyCreateDecryptedData
    pub fn create_decrypted(
        &self,
        algorithm: Algorithm,
        data: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, CFError> {
        let mut error: CFErrorRef = std::ptr::null_mut();

        let output = unsafe {
            SecKeyCreateDecryptedData(
                self.to_void() as _,
                algorithm.into(),
                CFData::from_buffer(data.as_ref()).as_concrete_TypeRef(),
                &mut error,
            )
        };

        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            let output = unsafe { CFData::wrap_under_create_rule(output) };
            Ok(output.to_vec())
        }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Translates to SecKeyIsAlgorithmSupported
    pub fn is_supported(&self, operation: OperationType, algorithm: Algorithm) -> bool {
        unsafe {
            SecKeyIsAlgorithmSupported(self.to_void() as _, operation.into(), algorithm.into()) == 1
        }
    }

    /// Translates to SecKeyGetBlockSize
    pub fn block_size(&self) -> usize {
        unsafe { SecKeyGetBlockSize(self.to_void() as _) }
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    /// Performs the Diffie-Hellman style of key exchange.
    pub fn key_exchange(
        &self,
        algorithm: Algorithm,
        public_key: &SecKey,
        size: usize,
    ) -> Result<Vec<u8>, CFError> {
        unsafe {
            let size = (
                CFString::wrap_under_get_rule(kSecKeyKeyExchangeParameterRequestedSize),
                CFNumber::from(size as i64),
            );
            let parameters = CFDictionary::from_CFType_pairs(&[size]);

            let mut error: CFErrorRef = std::ptr::null_mut();

            let output = SecKeyCopyKeyExchangeResult(
                self.to_void() as _,
                algorithm.into(),
                public_key.to_void() as _,
                parameters.as_concrete_TypeRef(),
                &mut error,
            );
            if !error.is_null() {
                Err(CFError::wrap_under_create_rule(error))
            } else {
                let output = CFData::wrap_under_create_rule(output);
                Ok(output.to_vec())
            }
        }
    }

    /// Retrieve key type.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn key_type(&self) -> KeyType {
        let attributes = self.attributes();
        let type_ = attributes
            .find(unsafe { kSecAttrKeyType }.to_void())
            .expect("found key without type");

        let type_ = unsafe { CFString::wrap_under_create_rule((*type_) as _) };
        KeyType::from_str(type_.as_concrete_TypeRef())
    }

    /// Retrieve key size.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn key_size(&self) -> usize {
        let attributes = self.attributes();
        let size = attributes
            .find(unsafe { kSecAttrKeySizeInBits }.to_void())
            .expect("found key without size");

        let size = unsafe { CFNumber::wrap_under_create_rule((*size) as _) };
        size.to_i64().unwrap() as _
    }

    /// Retrieve if key stored in secure enclave.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn secure_enclave(&self) -> bool {
        let attributes = self.attributes();

        if let Some(token_id) = attributes.find(unsafe { kSecAttrTokenID }.to_void()) {
            let token_id = unsafe { CFString::wrap_under_create_rule((*token_id) as _) };
            token_id.as_concrete_TypeRef() == unsafe { kSecAttrTokenIDSecureEnclave }
        } else {
            false
        }
    }

    /// Retrieve key label.
    // TODO: does't seem to work
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn label(&self) -> Option<String> {
        let attributes = self.attributes();

        if let Some(label) = attributes.find(unsafe { kSecAttrLabel }.to_void()) {
            let label = unsafe { CFString::wrap_under_create_rule((*label) as _) };
            Some(label.to_string())
        } else {
            None
        }
    }

    /// Retrieve if key is permanent.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn permanent(&self) -> bool {
        let attributes = self.attributes();

        if let Some(permanent) = attributes.find(unsafe { kSecAttrIsPermanent }.to_void()) {
            let permanent = unsafe { CFBoolean::wrap_under_create_rule((*permanent) as _) };
            permanent.into()
        } else {
            false
        }
    }

    /// Retrieve key application tag.
    // TODO: does't seem to work
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn application_tag(&self) -> Option<String> {
        let attributes = self.attributes();

        if let Some(application_tag) = attributes.find(unsafe { kSecAttrApplicationTag }.to_void())
        {
            let application_tag =
                unsafe { CFString::wrap_under_create_rule((*application_tag) as _) };
            Some(application_tag.to_string())
        } else {
            None
        }
    }

    /// Retrieve if key is treated like an iOS keychain item.
    // TODO: does't seem to work
    #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    pub fn data_protection(&self) -> bool {
        let attributes = self.attributes();

        if let Some(data_protection) =
            attributes.find(unsafe { kSecUseDataProtectionKeychain }.to_void())
        {
            let data_protection =
                unsafe { CFBoolean::wrap_under_create_rule((*data_protection) as _) };
            data_protection.into()
        } else {
            false
        }
    }

    /// Retrieve if key is exportable.
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub fn exportable(&self) -> bool {
        let attributes = self.attributes();

        if let Some(exportable) = attributes.find(unsafe { kSecAttrIsExtractable }.to_void()) {
            let exportable = unsafe { CFBoolean::wrap_under_create_rule((*exportable) as _) };
            exportable.into()
        } else {
            true
        }
    }
}

// FIXME
impl fmt::Debug for SecKey {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "SecKey")
    }
}

/// Represents supported operation types.
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub enum OperationType {
    /// Decryption.
    Decrypt,
    /// Encryption.
    Encrypt,
    /// Key exchange.
    KeyExchange,
    /// Signing.
    Sign,
    /// Verifying.
    Verify,
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
impl From<OperationType> for SecKeyOperationType {
    fn from(type_: OperationType) -> Self {
        match type_ {
            OperationType::Decrypt => kSecKeyOperationTypeDecrypt,
            OperationType::Encrypt => kSecKeyOperationTypeEncrypt,
            OperationType::KeyExchange => kSecKeyOperationTypeKeyExchange,
            OperationType::Sign => kSecKeyOperationTypeSign,
            OperationType::Verify => kSecKeyOperationTypeVerify,
        }
    }
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn sign() -> Result<(), CFError> {
    let private_key = SecKey::create(KeyType::EcSec, 521).build()?;
    let signature =
        private_key.create_signature(Algorithm::ECDSASignatureMessageX962SHA512, "test")?;

    let public_key = private_key
        .public_key()
        .expect("no corresponding public key found");
    assert!(public_key.verify_signature(
        Algorithm::ECDSASignatureMessageX962SHA512,
        "test",
        signature
    )?);

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn encrypt() -> Result<(), CFError> {
    let private_key = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key = private_key
        .public_key()
        .expect("no corresponding public key found");

    let encrypted = public_key.create_encrypted(
        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM,
        "test",
    )?;
    let decrypted = private_key.create_decrypted(
        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM,
        encrypted,
    )?;

    assert_eq!(decrypted.as_slice(), "test".as_bytes());

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn is_supported() -> Result<(), CFError> {
    let private_key = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key = private_key
        .public_key()
        .expect("no corresponding public key found");

    // Sign/Verify
    assert!(private_key.is_supported(
        OperationType::Sign,
        Algorithm::ECDSASignatureMessageX962SHA512
    ));
    assert!(public_key.is_supported(
        OperationType::Verify,
        Algorithm::ECDSASignatureMessageX962SHA512
    ));

    // Sign/Verify wrong algorithm
    assert!(!private_key.is_supported(OperationType::Sign, Algorithm::RSASignatureMessagePSSSHA512));
    assert!(!public_key.is_supported(
        OperationType::Verify,
        Algorithm::RSASignatureMessagePSSSHA512
    ));

    // Encrypt/Decrypt
    assert!(public_key.is_supported(
        OperationType::Encrypt,
        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM
    ));
    assert!(private_key.is_supported(
        OperationType::Decrypt,
        Algorithm::ECIESEncryptionCofactorVariableIVX963SHA512AESGCM
    ));

    // Encrypt/Decrypt wrong algorithm
    assert!(!public_key.is_supported(
        OperationType::Encrypt,
        Algorithm::RSAEncryptionOAEPSHA512AESGCM
    ));
    assert!(!private_key.is_supported(
        OperationType::Decrypt,
        Algorithm::RSAEncryptionOAEPSHA512AESGCM
    ));

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn block_size() -> Result<(), CFError> {
    let key = SecKey::create(KeyType::EcSec, 384).build()?;
    assert_eq!(key.block_size(), 104);

    let key = SecKey::create(KeyType::EcSec, 521).build()?;
    assert_eq!(key.block_size(), 141);

    let key = SecKey::create(KeyType::Rsa, 2048).build()?;
    assert_eq!(key.block_size(), 256);

    let key = SecKey::create(KeyType::Rsa, 4096).build()?;
    assert_eq!(key.block_size(), 512);

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn import_export() -> Result<(), CFError> {
    let private_key = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key = private_key
        .public_key()
        .expect("no corresponding public key found");

    SecKey::import(
        KeyType::EcSec,
        KeyClass::Private,
        521,
        private_key.export()?,
    )?;
    SecKey::import(KeyType::EcSec, KeyClass::Public, 521, public_key.export()?)?;

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn key_exchange() -> Result<(), CFError> {
    let private_key_bob = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key_bob = private_key_bob
        .public_key()
        .expect("no corresponding public key found");

    let private_key_alice = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key_alice = private_key_alice
        .public_key()
        .expect("no corresponding public key found");

    let secret_bob = private_key_bob.key_exchange(
        Algorithm::ECDHKeyExchangeCofactorX963SHA512,
        &public_key_alice,
        128,
    )?;
    let secret_alice = private_key_alice.key_exchange(
        Algorithm::ECDHKeyExchangeCofactorX963SHA512,
        &public_key_bob,
        128,
    )?;

    assert_eq!(secret_bob, secret_alice);

    Ok(())
}

#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
#[test]
fn query() -> Result<(), CFError> {
    let private_key = SecKey::create(KeyType::EcSec, 521).build()?;
    let public_key = private_key
        .public_key()
        .expect("no corresponding public key found");

    assert_eq!(private_key.key_type(), KeyType::Ec);
    assert_eq!(public_key.key_type(), KeyType::Ec);

    assert_eq!(private_key.key_size(), 521);
    assert_eq!(public_key.key_size(), 521);

    assert!(!private_key.secure_enclave());
    assert!(!public_key.secure_enclave());

    assert!(!private_key.permanent());
    assert!(!public_key.permanent());

    /*#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    assert!(private_key.data_protection());
    #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    assert!(public_key.data_protection());*/

    assert!(private_key.exportable());
    assert!(public_key.exportable());

    Ok(())
}
