use crate::base::{SecKeychainAttributeList, SecKeychainItemRef};
#[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
use core_foundation_sys::base::{CFAllocatorRef, CFOptionFlags};
use core_foundation_sys::base::{CFTypeID, CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::CFDictionaryRef;
#[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
use core_foundation_sys::error::CFErrorRef;
#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
use core_foundation_sys::string::CFStringRef;
use std::os::raw::c_void;

pub enum OpaqueSecAccessControlRef {}
pub type SecAccessControlRef = *mut OpaqueSecAccessControlRef;

extern "C" {

    /// Returns the unique identifier of the opaque type to which a keychain item object belongs.
    pub fn SecKeychainItemGetTypeID() -> CFTypeID;

    /// Adds one or more items to a keychain.
    pub fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;

    /// Returns one or more keychain items that match a search query, or copies attributes of specific keychain items.
    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;

    /// Modifies items that match a search query.
    pub fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) -> OSStatus;

    /// Deletes items that match a search query.
    pub fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;

    /// # Legacy API
    pub fn SecKeychainItemModifyAttributesAndData(
        itemRef: SecKeychainItemRef,
        attrList: *const SecKeychainAttributeList,
        length: u32,
        data: *const c_void,
    ) -> OSStatus;

    pub fn SecKeychainItemFreeContent(
        attrList: *mut SecKeychainAttributeList,
        data: *mut c_void,
    ) -> OSStatus;

    pub fn SecKeychainItemDelete(itemRef: SecKeychainItemRef) -> OSStatus;

    #[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
    pub fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: SecAccessControlCreateFlags,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;

    #[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
    pub fn SecAccessControlGetTypeID() -> CFTypeID;

    #[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
    pub static kSecUseDataProtectionKeychain: CFStringRef;

    pub static kSecValueRef: CFStringRef;

    pub static kSecMatchItemList: CFStringRef;
}

#[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
pub type SecAccessControlCreateFlags = CFOptionFlags;
#[cfg(any(feature = "OSX_10_11", target_os = "ios"))]
pub const kSecAccessControlDevicePasscode: SecAccessControlCreateFlags = 1 << 4;
#[cfg(any(feature = "OSX_10_13", target_os = "ios"))]
pub const kSecAccessControlBiometryAny: SecAccessControlCreateFlags = 1 << 1;
#[cfg(any(feature = "OSX_10_13", target_os = "ios"))]
pub const kSecAccessControlBiometryCurrentSet: SecAccessControlCreateFlags = 1 << 3;
#[cfg(any(feature = "OSX_10_10", target_os = "ios"))]
pub const kSecAccessControlUserPresence: SecAccessControlCreateFlags = 1 << 0;
#[cfg(any(feature = "OSX_10_15", target_os = "ios"))]
pub const kSecAccessControlWatch: SecAccessControlCreateFlags = 1 << 5;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub const kSecAccessControlAnd: SecAccessControlCreateFlags = 1 << 15;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub const kSecAccessControlOr: SecAccessControlCreateFlags = 1 << 14;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub const kSecAccessControlApplicationPassword: SecAccessControlCreateFlags = 1 << 31;
#[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
pub const kSecAccessControlPrivateKeyUsage: SecAccessControlCreateFlags = 1 << 30;
