use core::fmt::Debug;

/// Guest ABI pointer-width description used for host and WASM memory layouts.
pub trait Guest {
    /// Unsigned pointer-sized integer used by the guest ABI.
    type Usize: Copy + Debug + Eq;
    /// Signed pointer-sized integer used by the guest ABI.
    type Isize: Copy + Debug + Eq;

    /// Byte width of `Usize`.
    const USIZE_SIZE: usize;
    /// ABI alignment of `Usize`.
    const USIZE_ALIGN: usize;
    /// ABI alignment value encoded in the guest `Usize` type.
    const USIZE_ALIGN_VALUE: Self::Usize;
}

/// WASM32 guest ABI marker.
#[derive(Clone)]
pub struct Wasm32;

/// WASM64 guest ABI marker.
#[derive(Clone)]
pub struct Wasm64;

impl Guest for Wasm32 {
    type Usize = u32;
    type Isize = i32;

    const USIZE_SIZE: usize = 4;
    const USIZE_ALIGN: usize = 4;
    const USIZE_ALIGN_VALUE: Self::Usize = 4;
}

impl Guest for Wasm64 {
    type Usize = u64;
    type Isize = i64;

    const USIZE_SIZE: usize = 8;
    const USIZE_ALIGN: usize = 8;
    const USIZE_ALIGN_VALUE: Self::Usize = 8;
}

/// C-compatible guest slice header containing base address and byte length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slice<A: Guest> {
    pub base: A::Usize,
    pub len: A::Usize,
}

impl<A: Guest> Slice<A> {
    /// Returns the encoded size of this guest slice header.
    pub const fn size() -> usize {
        core::mem::size_of::<Slice<A>>()
    }

    /// Returns the encoded alignment of this guest slice header.
    pub const fn align() -> usize {
        core::mem::align_of::<Slice<A>>()
    }
}
