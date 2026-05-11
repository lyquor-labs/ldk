use core::fmt::Debug;

pub trait Guest {
    type Usize: Copy + Debug + Eq;
    type Isize: Copy + Debug + Eq;

    const USIZE_SIZE: usize;
    const USIZE_ALIGN: usize;
    const USIZE_ALIGN_VALUE: Self::Usize;
}

#[derive(Clone)]
pub struct Wasm32;

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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Slice<A: Guest> {
    pub base: A::Usize,
    pub len: A::Usize,
}

impl<A: Guest> Slice<A> {
    pub const fn size() -> usize {
        core::mem::size_of::<Slice<A>>()
    }

    pub const fn align() -> usize {
        core::mem::align_of::<Slice<A>>()
    }
}
