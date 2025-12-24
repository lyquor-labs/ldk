use std::any::Any;

use super::{Immutable, Mutable, internal};
use crate::{Address, Bytes, CallContext, LyquidID, LyquidResult, NodeID, upc::CachePtr};
use internal::{StateAccessor, sealed};

/// UPC prepare context, which is allowed to only read the network state variables.
pub struct PrepareContextImpl<S>
where
    S: StateAccessor,
{
    pub lyquid_id: LyquidID,
    pub node_id: NodeID,
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
            lyquid_id: ctx.lyquid_id,
            node_id: ctx.node_id.unwrap(),
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
    pub lyquid_id: LyquidID,
    pub node_id: NodeID,
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
            lyquid_id: ctx.lyquid_id,
            node_id: ctx.node_id.unwrap(),
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

/// UPC response context, which is allowed to only read the network state variables.
pub struct ResponseContextImpl<S>
where
    S: StateAccessor,
{
    pub lyquid_id: LyquidID,
    pub node_id: NodeID,
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
            lyquid_id: ctx.lyquid_id,
            node_id: ctx.node_id.unwrap(),
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

// TODO: Is this thread-safe? (Or do we need to consider it?) Because instance functions can run in
// parallel. However, UPC logic may confine the access of Cache so may not be any parallel possible
// runs.
impl Cache {
    #[doc(hidden)]
    pub fn new(cache_ptr: Option<CachePtr>) -> Self {
        Self {
            inner: cache_ptr.map(|addr| unsafe { Box::from_raw(addr as *mut CacheMem) }),
        }
    }

    // NOTE: Naming mimicks std::cell::OnceCell

    pub fn set<T: 'static>(&mut self, data: T) {
        self.inner = Some(Box::new(CacheMem(Box::new(data))));
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.inner.as_ref().and_then(|e| e.0.as_ref().downcast_ref())
    }

    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.inner.as_mut().and_then(|e| e.0.as_mut().downcast_mut())
    }

    pub fn get_or_init<T: 'static>(&mut self, init: impl FnOnce() -> T) -> &T {
        if self.inner.is_none() {
            self.inner = Some(Box::new(CacheMem(Box::new(init()))));
        }
        self.inner
            .as_ref()
            .unwrap()
            .0
            .as_ref()
            .downcast_ref()
            .expect("UPC: incorrect cache type.")
    }

    pub fn get_mut_or_init<T: 'static>(&mut self, init: impl FnOnce() -> T) -> &mut T {
        if self.inner.is_none() {
            self.inner = Some(Box::new(CacheMem(Box::new(init()))));
        }
        self.inner
            .as_mut()
            .unwrap()
            .0
            .as_mut()
            .downcast_mut()
            .expect("UPC: incorrect cache type.")
    }

    #[doc(hidden)]
    pub fn take_cache(&mut self) -> Option<Box<CacheMem>> {
        self.inner.take()
    }
}
