use core_foundation_sys::string::CFStringRef;

extern "C" {
    pub static kSecClass: CFStringRef;
    pub static kSecClassInternetPassword: CFStringRef;
    pub static kSecClassGenericPassword: CFStringRef;
    pub static kSecClassCertificate: CFStringRef;
    pub static kSecClassKey: CFStringRef;
    pub static kSecClassIdentity: CFStringRef;

    pub static kSecMatchLimit: CFStringRef;
    pub static kSecMatchLimitAll: CFStringRef;

    pub static kSecReturnData: CFStringRef;
    pub static kSecReturnAttributes: CFStringRef;
    pub static kSecReturnRef: CFStringRef;
    pub static kSecReturnPersistentRef: CFStringRef;

    pub static kSecMatchSearchList: CFStringRef;

    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrLabel: CFStringRef;

    pub static kSecAttrKeySizeInBits: CFStringRef;

    pub static kSecPrivateKeyAttrs: CFStringRef;
    pub static kSecPublicKeyAttrs: CFStringRef;
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub static kSecAttrTokenID: CFStringRef;
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub static kSecAttrTokenIDSecureEnclave: CFStringRef;
    pub static kSecAttrIsPermanent: CFStringRef;
    pub static kSecAttrApplicationTag: CFStringRef;
    pub static kSecAttrCanEncrypt: CFStringRef;
    pub static kSecAttrCanDecrypt: CFStringRef;
    pub static kSecAttrCanDerive: CFStringRef;
    pub static kSecAttrCanSign: CFStringRef;
    pub static kSecAttrCanVerify: CFStringRef;
    #[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
    pub static kSecAttrAccessControl: CFStringRef;
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    pub static kSecAttrSynchronizable: CFStringRef;
    pub static kSecAttrIsExtractable: CFStringRef;

    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    pub static kSecAttrKeyTypeRSA: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeDSA: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeAES: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeDES: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyType3DES: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeRC4: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeRC2: CFStringRef;
    #[cfg(target_os = "macos")]
    pub static kSecAttrKeyTypeCAST: CFStringRef;
    #[cfg(feature = "OSX_10_9")]
    pub static kSecAttrKeyTypeEC: CFStringRef;

    pub static kSecAttrAccessGroup: CFStringRef;
    pub static kSecAttrAccessGroupToken: CFStringRef;

    pub static kSecAttrKeyClass: CFStringRef;
    pub static kSecAttrKeyClassPublic: CFStringRef;
    pub static kSecAttrKeyClassPrivate: CFStringRef;
    pub static kSecAttrKeyClassSymmetric: CFStringRef;

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub static kSecKeyKeyExchangeParameterRequestedSize: CFStringRef;
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    pub static kSecKeyKeyExchangeParameterSharedInfo: CFStringRef;

    #[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
    pub static kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: CFStringRef;
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    pub static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    pub static kSecAttrAccessibleWhenUnlocked: CFStringRef;
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    pub static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    pub static kSecAttrAccessibleAfterFirstUnlock: CFStringRef;
}
