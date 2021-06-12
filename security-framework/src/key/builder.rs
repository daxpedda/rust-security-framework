use std::fmt;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrAccessibleAfterFirstUnlock,
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, kSecAttrAccessibleWhenUnlocked,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationTag, kSecAttrCanDecrypt,
    kSecAttrCanDerive, kSecAttrCanEncrypt, kSecAttrCanSign, kSecAttrCanVerify,
    kSecAttrIsExtractable, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrLabel, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecPrivateKeyAttrs,
    kSecPublicKeyAttrs,
};
use security_framework_sys::key::SecKeyCreateRandomKey;
#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
use security_framework_sys::keychain_item::kSecAccessControlWatch;
#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
use security_framework_sys::keychain_item::kSecUseDataProtectionKeychain;
use security_framework_sys::keychain_item::{
    kSecAccessControlAnd, kSecAccessControlApplicationPassword, kSecAccessControlDevicePasscode,
    kSecAccessControlOr, kSecAccessControlPrivateKeyUsage, SecAccessControlCreateFlags,
    SecAccessControlCreateWithFlags, SecAccessControlGetTypeID, SecAccessControlRef,
};
#[cfg(any(feature = "OSX_10_13", target_os = "ios"))]
use security_framework_sys::keychain_item::{
    kSecAccessControlBiometryAny, kSecAccessControlBiometryCurrentSet,
};

use super::SecKey;
use crate::item::KeyType;
#[cfg(test)]
use crate::item::{ItemClass, ItemSearchOptions, Reference};

/// Key builder.
#[derive(Clone, Debug)]
pub struct SecKeyBuilder {
    type_: KeyType,
    size: usize,
    secure_enclave: bool,
    label: Type<Option<String>>,
    permanent: Type<bool>,
    application_tag: Type<Option<String>>,
    encrypt: bool,
    decrypt: bool,
    derive: Type<bool>,
    sign: bool,
    verify: bool,
    access_control: Option<SecKeyAccessControl>,
    data_protection: Type<bool>,
    export: bool,
}

/// Represents which key this attribute should apply to.
pub enum SecKeyBuilderType {
    /// Attribute should apply to private key.
    Private,
    /// Attribute should apply to public key.
    Public,
}

impl SecKeyBuilder {
    pub(crate) fn new(type_: KeyType, size: usize) -> Self {
        Self {
            type_,
            size,
            secure_enclave: false,
            label: Type {
                private: None,
                public: None,
            },
            permanent: Type {
                private: false,
                public: false,
            },
            application_tag: Type {
                private: None,
                public: None,
            },
            encrypt: true,
            decrypt: true,
            derive: Type {
                private: true,
                public: true,
            },
            sign: true,
            verify: true,
            access_control: None,
            data_protection: Type {
                private: true,
                public: true,
            },
            export: true,
        }
    }

    /// This keys type.
    pub fn r#type(&self) -> KeyType {
        self.type_
    }

    /// Set a type for this key.
    pub fn set_type(&mut self, r#type: KeyType) -> &mut Self {
        self.type_ = r#type;
        self
    }

    /// This keys size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Set a size for this key.
    pub fn set_size(&mut self, size: usize) -> &mut Self {
        self.size = size;
        self
    }

    /// Returns `true` if this key is to be stored in the secure enclave.
    pub fn secure_enclave(&self) -> bool {
        self.secure_enclave
    }

    /// Set if this key is to be stored in the secure enclave.
    pub fn set_secure_enclave(&mut self, secure_enclave: bool) -> &mut Self {
        self.secure_enclave = secure_enclave;
        self
    }

    /// This keys label.
    pub fn label(&self, r#type: SecKeyBuilderType) -> Option<&str> {
        self.label.get(r#type).as_deref()
    }

    /// Set a label for this key.
    pub fn set_label(&mut self, r#type: SecKeyBuilderType, label: Option<String>) -> &mut Self {
        self.label.set(r#type, label);
        self
    }

    /// Returns `true` if this key is to be stored permanently.
    pub fn permanent(&self, r#type: SecKeyBuilderType) -> bool {
        *self.permanent.get(r#type)
    }

    /// Set if this key is to be stored permanently.
    pub fn set_permanent(&mut self, r#type: SecKeyBuilderType, permanent: bool) -> &mut Self {
        self.permanent.set(r#type, permanent);
        self
    }

    /// This keys application tag.
    pub fn application_tag(&self, r#type: SecKeyBuilderType) -> Option<&str> {
        self.application_tag.get(r#type).as_deref()
    }

    /// Set an application tag for this key.
    pub fn set_application_tag(
        &mut self,
        r#type: SecKeyBuilderType,
        application_tag: Option<String>,
    ) -> &mut Self {
        self.application_tag.set(r#type, application_tag);
        self
    }

    /// Returns `true` if this key can be used for encryption.
    pub fn encrypt(&self) -> bool {
        self.encrypt
    }

    /// Set if this key can be used for encryption.
    pub fn set_encrypt(&mut self, encrypt: bool) -> &mut Self {
        self.encrypt = encrypt;
        self
    }

    /// Returns `true` if this key can be used for decryption.
    pub fn decrypt(&self) -> bool {
        self.decrypt
    }

    /// Set if this key can be used for decryption.
    pub fn set_decrypt(&mut self, decrypt: bool) -> &mut Self {
        self.decrypt = decrypt;
        self
    }

    /// Returns `true` if this key can be used for derivation.
    pub fn derive(&self, r#type: SecKeyBuilderType) -> bool {
        *self.derive.get(r#type)
    }

    /// Set if this key can be used for derivation.
    pub fn set_derive(&mut self, r#type: SecKeyBuilderType, derive: bool) -> &mut Self {
        self.derive.set(r#type, derive);
        self
    }

    /// Returns `true` if this key can be used for signing.
    pub fn sign(&self) -> bool {
        self.sign
    }

    /// Set if this key can be used for signing.
    pub fn set_sign(&mut self, sign: bool) -> &mut Self {
        self.sign = sign;
        self
    }

    /// Returns `true` if this key can be used for verifying.
    pub fn verify(&self) -> bool {
        self.verify
    }

    /// Set if this key can be used for verifying.
    pub fn set_verify(&mut self, verify: bool) -> &mut Self {
        self.verify = verify;
        self
    }

    /// This keys access control configuration.
    pub fn access_control(&self) -> Option<SecKeyAccessControl> {
        self.access_control
    }

    /// Set this keys access control configuration.
    pub fn set_access_control(&mut self, access_control: Option<SecKeyAccessControl>) -> &mut Self {
        self.access_control = access_control;
        self
    }

    /// Returns `true` if this key is treated like an iOS keychain item. This is turned on by default.
    pub fn data_protection(&self, r#type: SecKeyBuilderType) -> bool {
        *self.data_protection.get(r#type)
    }

    /// Set if this key is treated like an iOS keychain item. This is turned on by default.
    pub fn set_data_protection(
        &mut self,
        r#type: SecKeyBuilderType,
        data_protection: bool,
    ) -> &mut Self {
        self.data_protection.set(r#type, data_protection);
        self
    }

    /// Returns `true` if this key is exportable.
    pub fn export(&self) -> bool {
        self.export
    }

    /// Set if this key is exportable.
    pub fn set_export(&mut self, export: bool) -> &mut Self {
        self.export = export;
        self
    }

    fn attributes(&self) -> Result<CFDictionary<CFString, CFType>, CFError> {
        let mut attributes = AttributeBuilder::default();

        unsafe {
            attributes.global.push((
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                self.type_.to_str().as_CFType(),
            ));
            attributes.global.push((
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(self.size as i64).as_CFType(),
            ));

            if self.secure_enclave {
                attributes.global.push((
                    CFString::wrap_under_get_rule(kSecAttrTokenID),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
                ));
            }

            if let Some(label) = &self.label.private {
                attributes.add_attribute_string(SecKeyBuilderType::Private, kSecAttrLabel, label);
            }
            if let Some(label) = &self.label.public {
                attributes.add_attribute_string(SecKeyBuilderType::Public, kSecAttrLabel, label);
            }

            if self.permanent.private {
                attributes.add_attribute_bool(
                    SecKeyBuilderType::Private,
                    kSecAttrIsPermanent,
                    true,
                );
            }
            if self.permanent.public {
                attributes.add_attribute_bool(SecKeyBuilderType::Public, kSecAttrIsPermanent, true);
            }

            if let Some(application_tag) = &self.application_tag.private {
                attributes.add_attribute_bytes(
                    SecKeyBuilderType::Private,
                    kSecAttrApplicationTag,
                    application_tag.as_bytes(),
                );
            }
            if let Some(application_tag) = &self.application_tag.public {
                attributes.add_attribute_bytes(
                    SecKeyBuilderType::Public,
                    kSecAttrApplicationTag,
                    application_tag.as_bytes(),
                );
            }

            if !self.encrypt {
                attributes.add_attribute_bool(SecKeyBuilderType::Public, kSecAttrCanEncrypt, false);
            }
            if !self.decrypt {
                attributes.add_attribute_bool(
                    SecKeyBuilderType::Private,
                    kSecAttrCanDecrypt,
                    false,
                );
            }

            if !self.derive.private {
                attributes.add_attribute_bool(SecKeyBuilderType::Private, kSecAttrCanDerive, false);
            }
            if !self.derive.public {
                attributes.add_attribute_bool(SecKeyBuilderType::Public, kSecAttrCanDerive, false);
            }

            if !self.verify {
                attributes.add_attribute_bool(SecKeyBuilderType::Public, kSecAttrCanVerify, false);
            }
            if !self.sign {
                attributes.add_attribute_bool(SecKeyBuilderType::Private, kSecAttrCanSign, false);
            }

            if let Some(access_control) = self.access_control {
                attributes.add_attribute(
                    SecKeyBuilderType::Private,
                    kSecAttrAccessControl,
                    access_control.build()?.as_CFType(),
                )
            }

            #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
            {
                attributes.add_attribute_bool(
                    SecKeyBuilderType::Private,
                    kSecUseDataProtectionKeychain,
                    self.data_protection.private,
                );
                attributes.add_attribute_bool(
                    SecKeyBuilderType::Public,
                    kSecUseDataProtectionKeychain,
                    self.data_protection.public,
                );
            }

            if !self.export {
                attributes.global.push((
                    CFString::wrap_under_get_rule(kSecAttrIsExtractable),
                    CFBoolean::false_value().as_CFType(),
                ));
            }
        }

        Ok(attributes.build())
    }

    /// Generate a new private/public key pair with the given properties.
    pub fn build(&self) -> Result<SecKey, CFError> {
        let parameters = self.attributes()?;

        let mut error: CFErrorRef = std::ptr::null_mut();

        let key = unsafe { SecKeyCreateRandomKey(parameters.as_concrete_TypeRef(), &mut error) };
        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            Ok(unsafe { SecKey::wrap_under_create_rule(key) })
        }
    }
}

/// Access control configuration for keys.
#[derive(Clone, Copy, Debug)]
pub struct SecKeyAccessControl {
    /// Key protection class.
    pub protection: SecKeyProtection,
    /// Key constrained.
    pub constraints: SecKeyConstraints,
    /// Use an app specific-password.
    pub password: bool,
    /// Enables private keys to be used when stored in a secure-enclave.
    pub key_usage: bool,
}

impl SecKeyAccessControl {
    /// Build a new access control configuration. See fields for more information on each parameter.
    pub fn new(
        protection: SecKeyProtection,
        constraints: SecKeyConstraints,
        password: bool,
        key_usage: bool,
    ) -> Self {
        Self {
            protection,
            constraints,
            password,
            key_usage,
        }
    }

    fn build(self) -> Result<SecAccessControl, CFError> {
        let mut constraints = self.constraints.build();

        if self.password {
            constraints |= kSecAccessControlApplicationPassword;
        }

        if self.key_usage {
            constraints |= kSecAccessControlPrivateKeyUsage;
        }

        let mut error: CFErrorRef = std::ptr::null_mut();

        let access_control = unsafe {
            SecAccessControlCreateWithFlags(
                std::ptr::null(),
                self.protection.to_str().as_CFTypeRef(),
                constraints,
                &mut error,
            )
        };
        if !error.is_null() {
            Err(unsafe { CFError::wrap_under_create_rule(error) })
        } else {
            Ok(unsafe { SecAccessControl::wrap_under_create_rule(access_control) })
        }
    }
}

/// Key protection class.
#[derive(Clone, Copy, Debug)]
pub enum SecKeyProtection {
    /// Application has to be in the foreground, the key can't be exported and the device has to be protected by a passcode.
    ForegroundLocalPasscode,
    /// Application has to be in the foreground and the key can't be exported.
    ForegroundLocal,
    /// Application has to be in the foreground and the key can be exported.
    Foreground,
    /// Application can be in the background and the key can't be exported.
    Local,
    /// Application can be in the background and the key can be exported.
    Unlocked,
}

impl SecKeyProtection {
    fn to_str(self) -> CFString {
        unsafe {
            let protection = match self {
                Self::ForegroundLocalPasscode => kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                Self::ForegroundLocal => kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                Self::Foreground => kSecAttrAccessibleWhenUnlocked,
                Self::Local => kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                Self::Unlocked => kSecAttrAccessibleAfterFirstUnlock,
            };

            CFString::wrap_under_get_rule(protection)
        }
    }
}

/// Key constraints.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecKeyConstraints {
    /// Key is protected by a passcode.
    pub passcode: bool,
    /// Key is protected by biometrics (TouchID/FaceID).
    /// Requires `any(feature = "OSX_10_13", target_os = "ios")`, otherwise is no-op.
    pub biometry: Option<SecKeyBiometry>,
    /// Key is unlocked by watch.
    /// Requires `any(feature = "OSX_10_15", target_os = "ios")`, otherwise is no-op.
    pub watch: bool,
    /// When this is set to `true`, **all** key constraints have to be fullfilled for the key to be
    /// unlocked, opposed to only **one** constraint when this is set to `false`.
    pub all: bool,
}

/// Key biometric constraint.
#[derive(Clone, Copy, Debug)]
pub enum SecKeyBiometry {
    /// The key is unlocked with the currently enrolled set of biometrics. When the FaceID user is changed or TouchID fingers are added or removed, keys are invalidated.
    Current,
    /// The key is unlocked with any set of biometrics, even if they change.
    Any,
}

impl SecKeyConstraints {
    /// Build a new access control key constraint configuration. See fields for more information on each parameter.
    pub fn new(passcode: bool, biometry: Option<SecKeyBiometry>, watch: bool, all: bool) -> Self {
        Self {
            passcode,
            biometry,
            watch,
            all,
        }
    }

    fn build(self) -> SecAccessControlCreateFlags {
        let mut flags_num = 0;
        let mut flags = SecAccessControlCreateFlags::default();

        if self.passcode {
            flags |= kSecAccessControlDevicePasscode;
            flags_num += 1;
        }

        #[cfg(any(feature = "OSX_10_13", target_os = "ios"))]
        if let Some(biometry) = self.biometry {
            match biometry {
                SecKeyBiometry::Current => flags |= kSecAccessControlBiometryCurrentSet,
                SecKeyBiometry::Any => flags |= kSecAccessControlBiometryAny,
            }

            flags_num += 1;
        }

        #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
        if self.watch {
            flags |= kSecAccessControlWatch;
            flags_num += 1;
        }

        if flags_num > 1 {
            if self.all {
                flags |= kSecAccessControlAnd;
            } else {
                flags |= kSecAccessControlOr;
            }
        }

        flags
    }
}

#[derive(Clone, Debug)]
struct Type<T> {
    private: T,
    public: T,
}

impl<T> Type<T> {
    fn get(&self, type_: SecKeyBuilderType) -> &T {
        match type_ {
            SecKeyBuilderType::Private => &self.private,
            SecKeyBuilderType::Public => &self.public,
        }
    }

    fn set(&mut self, type_: SecKeyBuilderType, value: T) {
        match type_ {
            SecKeyBuilderType::Private => self.private = value,
            SecKeyBuilderType::Public => self.public = value,
        }
    }
}

#[derive(Default)]
struct AttributeBuilder {
    global: Vec<(CFString, CFType)>,
    private: Vec<(CFString, CFType)>,
    public: Vec<(CFString, CFType)>,
}

impl AttributeBuilder {
    fn add_attribute(&mut self, type_: SecKeyBuilderType, key: CFStringRef, value: CFType) {
        let key = unsafe { CFString::wrap_under_get_rule(key) };

        match type_ {
            SecKeyBuilderType::Private => self.private.push((key, value)),
            SecKeyBuilderType::Public => self.public.push((key, value)),
        }
    }

    fn add_attribute_string(&mut self, type_: SecKeyBuilderType, key: CFStringRef, value: &str) {
        self.add_attribute(type_, key, CFString::new(value).as_CFType());
    }

    fn add_attribute_bool(&mut self, type_: SecKeyBuilderType, key: CFStringRef, value: bool) {
        self.add_attribute(type_, key, CFBoolean::from(value).as_CFType());
    }

    fn add_attribute_bytes(&mut self, type_: SecKeyBuilderType, key: CFStringRef, value: &[u8]) {
        self.add_attribute(type_, key, CFData::from_buffer(value).as_CFType());
    }

    fn build(mut self) -> CFDictionary<CFString, CFType> {
        if !self.private.is_empty() {
            let private = CFDictionary::from_CFType_pairs(&self.private);
            self.global.push((
                unsafe { CFString::wrap_under_get_rule(kSecPrivateKeyAttrs) },
                private.as_CFType(),
            ));
        }

        if !self.public.is_empty() {
            let public = CFDictionary::from_CFType_pairs(&self.public);
            self.global.push((
                unsafe { CFString::wrap_under_get_rule(kSecPublicKeyAttrs) },
                public.as_CFType(),
            ));
        }

        CFDictionary::from_CFType_pairs(&self.global)
    }
}

declare_TCFType! {
    /// A type representing a access control configuration.
    SecAccessControl, SecAccessControlRef
}
impl_TCFType!(
    SecAccessControl,
    SecAccessControlRef,
    SecAccessControlGetTypeID
);

unsafe impl Sync for SecAccessControl {}
unsafe impl Send for SecAccessControl {}

// FIXME
impl fmt::Debug for SecAccessControl {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("SecAccessControl")
    }
}

#[test]
fn builder() -> Result<(), CFError> {
    let mut builder = SecKey::create(KeyType::Rsa, 4096);
    builder
        .set_label(
            SecKeyBuilderType::Private,
            Some(String::from("builder-test")),
        )
        .set_label(
            SecKeyBuilderType::Public,
            Some(String::from("builder-test")),
        )
        .set_permanent(SecKeyBuilderType::Private, true)
        .set_permanent(SecKeyBuilderType::Public, true)
        .set_application_tag(
            SecKeyBuilderType::Private,
            Some(String::from("io.security-framework.test")),
        )
        .set_application_tag(
            SecKeyBuilderType::Public,
            Some(String::from("io.security-framework.test")),
        )
        .set_decrypt(false)
        .set_encrypt(false)
        .set_derive(SecKeyBuilderType::Private, false)
        .set_derive(SecKeyBuilderType::Public, false)
        .set_sign(false)
        .set_verify(false)
        .set_export(false);
    #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    builder
        .set_data_protection(SecKeyBuilderType::Private, false)
        .set_data_protection(SecKeyBuilderType::Public, false);
    let private_key = builder.build()?;
    let public_key = private_key.public_key().expect("public key not found");

    assert_eq!(private_key.key_type(), KeyType::Rsa);
    assert_eq!(public_key.key_type(), KeyType::Rsa);

    assert_eq!(private_key.key_size(), 4096);
    assert_eq!(public_key.key_size(), 4096);

    assert!(!private_key.secure_enclave());
    assert!(!public_key.secure_enclave());

    /*assert_eq!(
        private_key.label(),
        Some(String::from("builder-test"))
    );
    assert_eq!(
        public_key.label(),
        Some(String::from("builder-test"))
    );*/

    assert!(private_key.permanent());
    assert!(public_key.permanent());

    /*assert_eq!(
        private_key.application_tag(),
        Some(String::from("io.security-framework.test"))
    );
    assert_eq!(
        public_key.application_tag(),
        Some(String::from("io.security-framework.test"))
    );*/

    #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    {
        assert!(!private_key.data_protection());
        assert!(!public_key.data_protection());
    }

    assert!(!private_key.exportable());

    ItemSearchOptions::new()
        .class(ItemClass::key())
        .match_item_list([&Reference::Key(private_key)])
        .delete()
        .expect("private key deletion failed");
    ItemSearchOptions::new()
        .class(ItemClass::key())
        .match_item_list([&Reference::Key(public_key)])
        .delete()
        .expect("public key deletion failed");

    Ok(())
}

#[test]
fn export() -> Result<(), CFError> {
    let key = SecKey::create(KeyType::Rsa, 4096)
        .set_export(false)
        .build()?;
    assert!(key.export().is_err());

    Ok(())
}
