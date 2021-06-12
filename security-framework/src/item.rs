//! Support to search for items in a keychain.

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::date::CFDate;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFCopyDescription, CFGetTypeID, CFRelease, CFTypeRef};
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::item::*;
use security_framework_sys::keychain_item::{
    kSecMatchItemList, SecItemCopyMatching, SecItemDelete,
};
use std::collections::HashMap;
use std::fmt;
use std::ptr;

use crate::base::Result;
use crate::certificate::SecCertificate;
use crate::cvt;
use crate::identity::SecIdentity;
use crate::key::SecKey;
#[cfg(target_os = "macos")]
use crate::os::macos::keychain::SecKeychain;

/// Specifies the type of items to search for.
#[derive(Debug, Copy, Clone)]
pub struct ItemClass(CFStringRef);

impl ItemClass {
    /// Look for `SecKeychainItem`s corresponding to generic passwords.
    #[inline(always)]
    pub fn generic_password() -> Self {
        unsafe { Self(kSecClassGenericPassword) }
    }

    /// Look for `SecKeychainItem`s corresponding to internet passwords.
    #[inline(always)]
    pub fn internet_password() -> Self {
        unsafe { Self(kSecClassInternetPassword) }
    }

    /// Look for `SecCertificate`s.
    #[inline(always)]
    pub fn certificate() -> Self {
        unsafe { Self(kSecClassCertificate) }
    }

    /// Look for `SecKey`s.
    #[inline(always)]
    pub fn key() -> Self {
        unsafe { Self(kSecClassKey) }
    }

    /// Look for `SecIdentity`s.
    #[inline(always)]
    pub fn identity() -> Self {
        unsafe { Self(kSecClassIdentity) }
    }

    #[inline]
    fn to_value(self) -> CFType {
        unsafe { CFType::wrap_under_get_rule(self.0 as *const _) }
    }
}

/// Specifies the number of results returned by a search
#[derive(Debug, Copy, Clone)]
pub enum Limit {
    /// Always return all results
    All,

    /// Return up to the specified number of results
    Max(i64),
}

impl Limit {
    #[inline]
    fn to_value(self) -> CFType {
        match self {
            Self::All => unsafe { CFString::wrap_under_get_rule(kSecMatchLimitAll).as_CFType() },
            Self::Max(l) => CFNumber::from(l).as_CFType(),
        }
    }
}

impl From<i64> for Limit {
    fn from(limit: i64) -> Self {
        Self::Max(limit)
    }
}

/// A builder type to search for items in keychains.
#[derive(Default)]
pub struct ItemSearchOptions {
    #[cfg(target_os = "macos")]
    keychains: Option<CFArray<SecKeychain>>,
    #[cfg(not(target_os = "macos"))]
    keychains: Option<CFArray<CFType>>,
    class: Option<ItemClass>,
    load_refs: bool,
    load_persistent_refs: bool,
    load_attributes: bool,
    load_data: bool,
    limit: Option<Limit>,
    label: Option<CFString>,
    access_group: Option<CFString>,
    application_tag: Option<CFString>,
    key_class: Option<KeyClass>,
    match_item_list: Option<CFArray<CFType>>,
}

#[cfg(target_os = "macos")]
impl crate::ItemSearchOptionsInternals for ItemSearchOptions {
    #[inline]
    fn keychains(&mut self, keychains: &[SecKeychain]) -> &mut Self {
        self.keychains = Some(CFArray::from_CFTypes(keychains));
        self
    }
}

impl ItemSearchOptions {
    /// Creates a new builder with default options.
    #[inline(always)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Search only for items of the specified class.
    #[inline(always)]
    pub fn class(&mut self, class: ItemClass) -> &mut Self {
        self.class = Some(class);
        self
    }

    /// Load Security Framework objects (`SecCertificate`, `SecKey`, etc) for
    /// the results.
    #[inline(always)]
    pub fn load_refs(&mut self, load_refs: bool) -> &mut Self {
        self.load_refs = load_refs;
        self
    }

    /// Load persistent references to Security Framework objects for
    /// the results.
    #[inline(always)]
    pub fn load_persistent_refs(&mut self, load_persistent_refs: bool) -> &mut Self {
        self.load_persistent_refs = load_persistent_refs;
        self
    }

    /// Load Security Framework object attributes for
    /// the results.
    #[inline(always)]
    pub fn load_attributes(&mut self, load_attributes: bool) -> &mut Self {
        self.load_attributes = load_attributes;
        self
    }

    /// Load Security Framework objects data for
    /// the results.
    #[inline(always)]
    pub fn load_data(&mut self, load_data: bool) -> &mut Self {
        self.load_data = load_data;
        self
    }

    /// Limit the number of search results.
    ///
    /// If this is not called, the default limit is 1.
    #[inline(always)]
    pub fn limit<T: Into<Limit>>(&mut self, limit: T) -> &mut Self {
        self.limit = Some(limit.into());
        self
    }

    /// Search for an item with the given label.
    #[inline(always)]
    pub fn label(&mut self, label: &str) -> &mut Self {
        self.label = Some(CFString::new(label));
        self
    }

    /// Sets kSecAttrAccessGroup to kSecAttrAccessGroupToken
    #[inline(always)]
    pub fn access_group_token(&mut self) -> &mut Self {
        self.access_group =
            unsafe { Some(CFString::wrap_under_get_rule(kSecAttrAccessGroupToken)) };
        self
    }

    /// Search for an item with the given application tag.
    #[inline(always)]
    pub fn application_tag(&mut self, application_tag: &str) -> &mut Self {
        self.application_tag = Some(CFString::new(application_tag));
        self
    }

    /// Search only for items of the specified key class.
    #[inline(always)]
    pub fn key_class(&mut self, key_class: KeyClass) -> &mut Self {
        self.key_class = Some(key_class);
        self
    }

    /// Search for the given items.
    #[inline(always)]
    pub fn match_item_list<'a>(
        &mut self,
        match_item_list: impl IntoIterator<Item = &'a Reference>,
    ) -> &mut Self {
        self.match_item_list = Some(CFArray::from_CFTypes(
            &match_item_list
                .into_iter()
                .map(Reference::to_value)
                .collect::<Vec<_>>(),
        ));
        self
    }

    fn attributes(&self) -> CFDictionary<CFString, CFType> {
        let mut params = vec![];

        unsafe {
            if let Some(ref keychains) = self.keychains {
                params.push((
                    CFString::wrap_under_get_rule(kSecMatchSearchList),
                    keychains.as_CFType(),
                ));
            }

            if let Some(class) = self.class {
                params.push((CFString::wrap_under_get_rule(kSecClass), class.to_value()));
            }

            if self.load_refs {
                params.push((
                    CFString::wrap_under_get_rule(kSecReturnRef),
                    CFBoolean::true_value().as_CFType(),
                ));
            }

            if self.load_persistent_refs {
                params.push((
                    CFString::wrap_under_get_rule(kSecReturnPersistentRef),
                    CFBoolean::true_value().as_CFType(),
                ));
            }

            if self.load_attributes {
                params.push((
                    CFString::wrap_under_get_rule(kSecReturnAttributes),
                    CFBoolean::true_value().as_CFType(),
                ));
            }

            if self.load_data {
                params.push((
                    CFString::wrap_under_get_rule(kSecReturnData),
                    CFBoolean::true_value().as_CFType(),
                ));
            }

            if let Some(limit) = self.limit {
                params.push((
                    CFString::wrap_under_get_rule(kSecMatchLimit),
                    limit.to_value(),
                ));
            }

            if let Some(ref label) = self.label {
                params.push((
                    CFString::wrap_under_get_rule(kSecAttrLabel),
                    label.as_CFType(),
                ));
            }

            if let Some(ref access_group) = self.access_group {
                params.push((
                    CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                    access_group.as_CFType(),
                ));
            }

            if let Some(ref application_tag) = self.application_tag {
                params.push((
                    CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                    application_tag.as_CFType(),
                ));
            }

            if let Some(key_class) = self.key_class {
                params.push((
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    key_class.to_value(),
                ));
            }

            if let Some(match_item_list) = &self.match_item_list {
                params.push((
                    CFString::wrap_under_get_rule(kSecMatchItemList),
                    match_item_list.as_CFType(),
                ));
            }
        }

        CFDictionary::from_CFType_pairs(&params)
    }

    /// Search for objects.
    pub fn search(&self) -> Result<Vec<SearchResult>> {
        let params = self.attributes();

        unsafe {
            let mut ret = ptr::null();
            cvt(SecItemCopyMatching(params.as_concrete_TypeRef(), &mut ret))?;
            let type_id = CFGetTypeID(ret);

            let mut items = vec![];

            if type_id == CFArray::<CFType>::type_id() {
                let array: CFArray<CFType> = CFArray::wrap_under_create_rule(ret as *mut _);
                for item in array.iter() {
                    items.push(get_item(item.as_CFTypeRef()));
                }
            } else {
                items.push(get_item(ret));
                // This is a bit janky, but get_item uses wrap_under_get_rule
                // which bumps the refcount but we want create semantics
                CFRelease(ret);
            }

            Ok(items)
        }
    }

    /// Delete objects.
    pub fn delete(&self) -> Result<()> {
        let params = self.attributes();
        cvt(unsafe { SecItemDelete(params.as_concrete_TypeRef()) })
    }
}

#[cfg(target_os = "macos")]
unsafe fn get_item(item: CFTypeRef) -> SearchResult {
    use crate::os::macos::keychain_item::SecKeychainItem;

    let type_id = CFGetTypeID(item);

    if type_id == CFData::type_id() {
        let data = CFData::wrap_under_get_rule(item as *mut _);
        let mut buf = Vec::new();
        buf.extend_from_slice(data.bytes());
        return SearchResult::Data(buf);
    }

    if type_id == CFDictionary::<*const u8, *const u8>::type_id() {
        return SearchResult::Dict(CFDictionary::wrap_under_get_rule(item as *mut _));
    }

    let reference = if type_id == SecCertificate::type_id() {
        Reference::Certificate(SecCertificate::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKey::type_id() {
        Reference::Key(SecKey::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecIdentity::type_id() {
        Reference::Identity(SecIdentity::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKeychainItem::type_id() {
        Reference::KeychainItem(SecKeychainItem::wrap_under_get_rule(item as *mut _))
    } else {
        panic!("Got bad type from SecItemCopyMatching: {}", type_id);
    };

    SearchResult::Ref(reference)
}

#[cfg(not(target_os = "macos"))]
unsafe fn get_item(item: CFTypeRef) -> SearchResult {
    let type_id = CFGetTypeID(item);

    let reference = if type_id == SecCertificate::type_id() {
        Reference::Certificate(SecCertificate::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecKey::type_id() {
        Reference::Key(SecKey::wrap_under_get_rule(item as *mut _))
    } else if type_id == SecIdentity::type_id() {
        Reference::Identity(SecIdentity::wrap_under_get_rule(item as *mut _))
    } else if type_id == CFData::type_id() {
        Reference::PersistentReference(CFData::wrap_under_get_rule(item as *mut _).to_vec())
    } else {
        panic!("Got bad type from SecItemCopyMatching: {}", type_id);
    };

    SearchResult::Ref(reference)
}

/// An enum including all objects which can be found by `ItemSearchOptions`.
#[derive(Debug)]
pub enum Reference {
    /// A `SecIdentity`.
    Identity(SecIdentity),
    /// A `SecCertificate`.
    Certificate(SecCertificate),
    /// A `SecKey`.
    Key(SecKey),
    /// A `SecKeychainItem`.
    ///
    /// Only defined on OSX
    #[cfg(target_os = "macos")]
    KeychainItem(crate::os::macos::keychain_item::SecKeychainItem),
    /// A persistent reference.
    PersistentReference(Vec<u8>),
    #[doc(hidden)]
    __NonExhaustive,
}

impl Reference {
    fn to_value(&self) -> CFType {
        match self {
            Reference::Identity(identity) => identity.as_CFType(),
            Reference::Certificate(certificate) => certificate.as_CFType(),
            Reference::Key(key) => key.as_CFType(),
            #[cfg(target_os = "macos")]
            Reference::KeychainItem(keychain_item) => keychain_item.as_CFType(),
            Reference::PersistentReference(persistent_reference) => {
                CFData::from_buffer(persistent_reference).as_CFType()
            }
            Reference::__NonExhaustive => unreachable!(),
        }
    }
}

/// An individual search result.
pub enum SearchResult {
    /// A reference to the Security Framework object, if asked for.
    Ref(Reference),
    /// A dictionary of data about the Security Framework object, if asked for.
    Dict(CFDictionary),
    /// The Security Framework object as bytes, if asked for.
    Data(Vec<u8>),
    /// An unknown representation of the Security Framework object.
    Other,
}

impl fmt::Debug for SearchResult {
    #[cold]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Ref(ref reference) => fmt
                .debug_struct("SearchResult::Ref")
                .field("reference", reference)
                .finish(),
            Self::Data(ref buf) => fmt
                .debug_struct("SearchResult::Data")
                .field("data", buf)
                .finish(),
            Self::Dict(_) => {
                let mut debug = fmt.debug_struct("SearchResult::Dict");
                for (k, v) in self.simplify_dict().unwrap() {
                    debug.field(&k, &v);
                }
                debug.finish()
            }
            Self::Other => write!(fmt, "SearchResult::Other"),
        }
    }
}

impl SearchResult {
    /// If the search result is a `CFDict`, simplify that to a
    /// `HashMap<String, String>`. This transformation isn't
    /// comprehensive, it only supports CFString, CFDate, and CFData
    /// value types.
    pub fn simplify_dict(&self) -> Option<HashMap<String, String>> {
        match *self {
            Self::Dict(ref d) => unsafe {
                let mut retmap = HashMap::new();
                let (keys, values) = d.get_keys_and_values();
                for (k, v) in keys.iter().zip(values.iter()) {
                    let keycfstr = CFString::wrap_under_get_rule(*k as *const _);
                    let val: String = match CFGetTypeID(*v) {
                        cfstring if cfstring == CFString::type_id() => {
                            format!("{}", CFString::wrap_under_get_rule(*v as *const _))
                        }
                        cfdata if cfdata == CFData::type_id() => {
                            let buf = CFData::wrap_under_get_rule(*v as *const _);
                            let mut vec = Vec::new();
                            vec.extend_from_slice(buf.bytes());
                            format!("{}", String::from_utf8_lossy(&vec))
                        }
                        cfdate if cfdate == CFDate::type_id() => format!(
                            "{}",
                            CFString::wrap_under_create_rule(CFCopyDescription(*v))
                        ),
                        _ => String::from("unknown"),
                    };
                    retmap.insert(format!("{}", keycfstr), val);
                }
                Some(retmap)
            },
            _ => None,
        }
    }
}

/// Types of `SecKey`s.
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum KeyType {
    Rsa,
    #[cfg(target_os = "macos")]
    Dsa,
    #[cfg(target_os = "macos")]
    Aes,
    #[cfg(target_os = "macos")]
    Des,
    #[cfg(target_os = "macos")]
    TripleDes,
    #[cfg(target_os = "macos")]
    Rc4,
    #[cfg(target_os = "macos")]
    Cast,
    /// Use `EcSec` instead. Querying or searching may still result or need `Ec`.
    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    Ec,
    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    EcSec,
}

#[allow(missing_docs)]
impl KeyType {
    #[deprecated = "use `KeyType::Rsa`"]
    #[inline(always)]
    pub fn rsa() -> Self {
        Self::Rsa
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::Dsa`"]
    #[inline(always)]
    pub fn dsa() -> Self {
        Self::Dsa
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::Aes`"]
    #[inline(always)]
    pub fn aes() -> Self {
        Self::Aes
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::Des`"]
    #[inline(always)]
    pub fn des() -> Self {
        Self::Des
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::TripleDes`"]
    #[inline(always)]
    pub fn triple_des() -> Self {
        Self::TripleDes
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::Rc4`"]
    #[inline(always)]
    pub fn rc4() -> Self {
        Self::Rc4
    }

    #[cfg(target_os = "macos")]
    #[deprecated = "use `KeyType::Cast`"]
    #[inline(always)]
    pub fn cast() -> Self {
        Self::Cast
    }

    #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
    #[deprecated = "use `KeyType::Ec`"]
    #[inline(always)]
    pub fn ec() -> Self {
        #[allow(deprecated)]
        Self::Ec
    }

    #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
    #[deprecated = "use `KeyType::EcSec`"]
    #[inline(always)]
    pub fn ec_sec() -> Self {
        Self::EcSec
    }

    pub(crate) fn to_str(self) -> CFString {
        unsafe {
            CFString::wrap_under_get_rule(match self {
                KeyType::Rsa => kSecAttrKeyTypeRSA,
                KeyType::Dsa => kSecAttrKeyTypeDSA,
                KeyType::Aes => kSecAttrKeyTypeAES,
                KeyType::Des => kSecAttrKeyTypeDES,
                KeyType::TripleDes => kSecAttrKeyType3DES,
                KeyType::Rc4 => kSecAttrKeyTypeRC4,
                KeyType::Cast => kSecAttrKeyTypeCAST,
                #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
                #[allow(deprecated)]
                KeyType::Ec => kSecAttrKeyTypeEC,
                #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
                KeyType::EcSec => kSecAttrKeyTypeECSECPrimeRandom,
            })
        }
    }

    pub(crate) fn from_str(string: CFStringRef) -> Self {
        unsafe {
            match string {
                type_ if type_ == kSecAttrKeyTypeRSA => KeyType::Rsa,
                type_ if type_ == kSecAttrKeyTypeDSA => KeyType::Dsa,
                type_ if type_ == kSecAttrKeyTypeAES => KeyType::Aes,
                type_ if type_ == kSecAttrKeyTypeDES => KeyType::Des,
                type_ if type_ == kSecAttrKeyType3DES => KeyType::TripleDes,
                type_ if type_ == kSecAttrKeyTypeRC4 => KeyType::Rc4,
                type_ if type_ == kSecAttrKeyTypeCAST => KeyType::Cast,
                #[cfg(any(feature = "OSX_10_9", target_os = "ios"))]
                #[allow(deprecated)]
                type_ if type_ == kSecAttrKeyTypeEC => KeyType::Ec,
                #[cfg(any(feature = "OSX_10_12", target_os = "ios"))]
                type_ if type_ == kSecAttrKeyTypeECSECPrimeRandom => KeyType::EcSec,
                _ => unreachable!("invalid string"),
            }
        }
    }
}

/// Classes of `SecKey`s.
#[derive(Debug, Copy, Clone)]
pub enum KeyClass {
    /// A public key of a public-private pair.
    Public,
    /// A private key of a public-private pair.
    Private,
    /// A private key used for symmetric-key encryption and decryption.
    Symmetric,
}

impl KeyClass {
    pub(crate) fn to_value(self) -> CFType {
        unsafe {
            let _type = match self {
                Self::Public => kSecAttrKeyClassPublic,
                Self::Private => kSecAttrKeyClassPrivate,
                Self::Symmetric => kSecAttrKeyClassSymmetric,
            };

            CFType::wrap_under_get_rule(_type as *const _)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn find_nothing() {
        assert!(ItemSearchOptions::new().search().is_err());
    }

    #[test]
    fn limit_two() {
        let results = ItemSearchOptions::new()
            .class(ItemClass::certificate())
            .limit(2)
            .search()
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn limit_all() {
        let results = ItemSearchOptions::new()
            .class(ItemClass::certificate())
            .limit(Limit::All)
            .search()
            .unwrap();
        assert!(results.len() >= 2);
    }
}
