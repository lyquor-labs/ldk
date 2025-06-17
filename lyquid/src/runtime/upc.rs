use std::any::Any;

use super::{Immutable, Mutable, internal};
use crate::{Address, Bytes, CallContext, LyquidError, LyquidResult, NodeID};

/// UPC callee context, which is allowed to only read the network state variables.
pub struct CalleeContextImpl<S>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub id: u64,
}

impl<S> CalleeContextImpl<S>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
{
    pub fn new(ctx: CallContext, id: u64) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new(&internal::PrefixedAccess::new(Vec::from(
                crate::VAR_CATALOG_PREFIX,
            )))?),
            id,
        })
    }
}

/// UPC request context, which is allowed to only read the network state variables and read/write the instance state variables.
pub struct RequestContextImpl<S, I>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
    I: internal::PrefixedAccessible<Vec<u8>>,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub instance: Mutable<I>,
    pub from: NodeID,
    pub id: u64,
}

impl<S, I> RequestContextImpl<S, I>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
    I: internal::PrefixedAccessible<Vec<u8>>,
{
    pub fn new(ctx: CallContext, from: NodeID, id: u64) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new(&internal::PrefixedAccess::new(Vec::from(
                crate::VAR_CATALOG_PREFIX,
            )))?),
            instance: Mutable::new(I::new(&internal::PrefixedAccess::new(Vec::from(
                crate::VAR_CATALOG_PREFIX,
            )))?),
            from,
            id,
        })
    }
}

/// UPC response context, which is allowed to only read the network state variables.
pub struct ResponseContextImpl<S>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub from: NodeID,
    pub id: u64,
    pub cache: Cache,
}

impl<S> ResponseContextImpl<S>
where
    S: internal::PrefixedAccessible<Vec<u8>>,
{
    pub fn new(ctx: CallContext, from: NodeID, id: u64, cache: Option<Vec<u8>>) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new(&internal::PrefixedAccess::new(Vec::from(
                crate::VAR_CATALOG_PREFIX,
            )))?),
            from,
            id,
            cache: Cache::new(cache)?,
        })
    }
}

/// We use this struct to hold a Box<dyn Any>, so we just leak a pointer to Cache instead of a dyn Any,
/// since a pointer of dyn Any needs a vtable to be constructed from a raw address.
#[doc(hidden)]
pub struct CachePointer(Box<dyn Any>);

pub struct Cache {
    inner: Option<Box<CachePointer>>,
}

impl Cache {
    #[doc(hidden)]
    pub fn new(cache_ptr: Option<Vec<u8>>) -> LyquidResult<Self> {
        let cache_ptr = match cache_ptr {
            Some(bytes) => Some(usize::from_be_bytes(
                bytes.try_into().map_err(|_| LyquidError::LyquorInput)?,
            )),
            None => None,
        };
        Ok(Self {
            inner: cache_ptr.map(|addr| unsafe { Box::from_raw(addr as *mut CachePointer) }),
        })
    }

    pub fn get_or_init<T: 'static>(&mut self, init: impl FnOnce() -> T) -> &mut T {
        if self.inner.is_none() {
            self.inner = Some(Box::new(CachePointer(Box::new(init()))));
        }
        self.inner
            .as_mut()
            .unwrap()
            .0
            .as_mut()
            .downcast_mut()
            .expect("cache error")
    }

    #[doc(hidden)]
    pub fn take_cache(&mut self) -> Option<Box<CachePointer>> {
        self.inner.take()
    }
}
