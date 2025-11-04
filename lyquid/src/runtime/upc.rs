use std::any::Any;

use super::{Immutable, Mutable, internal};
use crate::{Address, Bytes, CallContext, LyquidResult, NodeID, upc::CachePtr};
use internal::{OracleCertifyContext, StateAccessor, sealed};

/// UPC prepare context, which is allowed to only read the network state variables.
pub struct PrepareContextImpl<S>
where
    S: StateAccessor,
{
    pub origin: Address,
    pub caller: Address,
    pub input: Bytes,
    pub network: Immutable<S>,
    pub cache: Cache,
}

impl<S> PrepareContextImpl<S>
where
    S: StateAccessor,
{
    pub fn new(ctx: CallContext) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            cache: Cache::new(None),
        })
    }
}

/// UPC request context, which is allowed to only read the network state variables and read/write the instance state variables.
pub struct RequestContextImpl<S, I>
where
    S: StateAccessor,
    I: StateAccessor,
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
    S: StateAccessor,
    I: StateAccessor,
{
    pub fn new(ctx: CallContext, from: NodeID, id: u64) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            instance: Mutable::new(I::new()?),
            from,
            id,
        })
    }
}

impl<S: StateAccessor, I: StateAccessor> sealed::Sealed for RequestContextImpl<S, I> {}
impl<S: StateAccessor, I: StateAccessor> OracleCertifyContext for RequestContextImpl<S, I> {}

/// UPC response context, which is allowed to only read the network state variables.
pub struct ResponseContextImpl<S>
where
    S: StateAccessor,
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
    S: StateAccessor,
{
    pub fn new(ctx: CallContext, from: NodeID, id: u64, cache: Option<CachePtr>) -> LyquidResult<Self> {
        Ok(Self {
            origin: ctx.origin,
            caller: ctx.caller,
            input: ctx.input,
            network: Immutable::new(S::new()?),
            from,
            id,
            cache: Cache::new(cache),
        })
    }
}

/// We use this struct to hold a Box<dyn Any>, so we just leak a pointer to Cache instead of a dyn Any,
/// since a pointer of dyn Any needs a vtable to be constructed from a raw address.
#[doc(hidden)]
pub struct CacheMem(Box<dyn Any>);

pub struct Cache {
    inner: Option<Box<CacheMem>>,
}

impl Cache {
    #[doc(hidden)]
    pub fn new(cache_ptr: Option<CachePtr>) -> Self {
        Self {
            inner: cache_ptr.map(|addr| unsafe { Box::from_raw(addr as *mut CacheMem) }),
        }
    }

    pub fn get_or_init<T: 'static>(&mut self, init: impl FnOnce() -> T) -> &mut T {
        if self.inner.is_none() {
            self.inner = Some(Box::new(CacheMem(Box::new(init()))));
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
    pub fn take_cache(&mut self) -> Option<Box<CacheMem>> {
        self.inner.take()
    }
}
