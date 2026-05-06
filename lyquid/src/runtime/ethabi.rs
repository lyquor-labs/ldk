use std::string::String;
use std::vec::Vec;

use alloy_sol_types::{SolType, sol_data};

use lyquor_primitives::{Address, B256, Bytes, LyquidID, NodeID, RequiredLyquid, U64, U128, U256};

#[derive(Copy, Clone)]
pub struct EthAbiTypeDesc {
    pub base: &'static str,
    pub dims: [Option<u32>; MAX_DIMS],
    pub dims_len: u8,
    pub is_dynamic: bool,
}

const MAX_DIMS: usize = 8;
const EMPTY_DIMS: [Option<u32>; MAX_DIMS] = [None; MAX_DIMS];

impl EthAbiTypeDesc {
    pub const fn len(self) -> usize {
        let mut len = self.base.len();
        let mut i = 0usize;
        while i < self.dims_len as usize {
            len += dim_len(self.dims[i]);
            i += 1;
        }
        len
    }

    pub const fn with_dim(mut self, dim: Option<u32>) -> Self {
        if self.dims_len as usize >= MAX_DIMS {
            panic!("ethabi dims overflow");
        }
        self.dims[self.dims_len as usize] = dim;
        self.dims_len += 1;
        self
    }
}

const fn dim_len(dim: Option<u32>) -> usize {
    match dim {
        Some(val) => 2 + digits_u32(val),
        None => 2,
    }
}

const fn digits_u32(mut val: u32) -> usize {
    let mut digits = 1usize;
    while val >= 10 {
        val /= 10;
        digits += 1;
    }
    digits
}

const fn base_desc(base: &'static str, is_dynamic: bool) -> EthAbiTypeDesc {
    EthAbiTypeDesc {
        base,
        dims: EMPTY_DIMS,
        dims_len: 0,
        is_dynamic,
    }
}

pub trait EthAbiType: Sized {
    type SolType: SolType;

    const DESC: EthAbiTypeDesc;

    fn into_sol(self) -> <Self::SolType as SolType>::RustType;

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self>;
}

pub trait EthAbiParams: Sized {
    fn decode_params(data: &[u8]) -> Option<Self>;

    fn encode_params(self) -> Vec<u8>;
}

pub trait EthAbiReturnValue {
    fn encode_return(self) -> Vec<u8>;
}

pub trait EthAbiReturn: EthAbiReturnValue {
    const COUNT: usize;
    const TYPES: &'static [EthAbiTypeDesc];
}

impl EthAbiParams for () {
    fn decode_params(data: &[u8]) -> Option<Self> {
        <() as SolType>::abi_decode_params_validate(data).ok()
    }

    fn encode_params(self) -> Vec<u8> {
        <() as SolType>::abi_encode_params(&self)
    }
}

macro_rules! impl_eth_abi_params {
    ($($ty:ident $value:ident),+) => {
        impl<$($ty: EthAbiType),+> EthAbiParams for ($($ty,)+) {
            fn decode_params(data: &[u8]) -> Option<Self> {
                type SolTuple<$($ty),+> = ($(<$ty as EthAbiType>::SolType,)+);
                let ($($value,)+) =
                    <SolTuple<$($ty),+> as SolType>::abi_decode_params_validate(data).ok()?;
                Some(($(<$ty as EthAbiType>::from_sol($value)?,)+))
            }

            fn encode_params(self) -> Vec<u8> {
                type SolTuple<$($ty),+> = ($(<$ty as EthAbiType>::SolType,)+);
                let ($($value,)+) = self;
                let value = ($(<$ty as EthAbiType>::into_sol($value),)+);
                <SolTuple<$($ty),+> as SolType>::abi_encode_params(&value)
            }
        }
    };
}

impl_eth_abi_params!(A a);
impl_eth_abi_params!(A a, B b);
impl_eth_abi_params!(A a, B b, C c);
impl_eth_abi_params!(A a, B b, C c, D d);
impl_eth_abi_params!(A a, B b, C c, D d, E e);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n, O o);
impl_eth_abi_params!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n, O o, P p);

impl EthAbiReturnValue for () {
    fn encode_return(self) -> Vec<u8> {
        Vec::new()
    }
}

impl<T: EthAbiType> EthAbiReturnValue for T {
    fn encode_return(self) -> Vec<u8> {
        let value = T::into_sol(self);
        <T::SolType as SolType>::abi_encode(&value)
    }
}

macro_rules! impl_eth_abi_return_tuple {
    ($($ty:ident $value:ident),+) => {
        impl<$($ty: EthAbiType),+> EthAbiReturnValue for ($($ty,)+) {
            fn encode_return(self) -> Vec<u8> {
                type SolTuple<$($ty),+> = ($(<$ty as EthAbiType>::SolType,)+);
                let ($($value,)+) = self;
                let value = ($(<$ty as EthAbiType>::into_sol($value),)+);
                <SolTuple<$($ty),+> as SolType>::abi_encode_sequence(&value)
            }
        }

        impl<$($ty: EthAbiType),+> EthAbiReturn for ($($ty,)+) {
            const COUNT: usize = 0 $(+ {
                let _ = stringify!($ty);
                1
            })+;
            const TYPES: &'static [EthAbiTypeDesc] = &[$($ty::DESC,)+];
        }
    };
}

impl EthAbiReturn for () {
    const COUNT: usize = 0;
    const TYPES: &'static [EthAbiTypeDesc] = &[];
}

impl<T: EthAbiType> EthAbiReturn for T {
    const COUNT: usize = 1;
    const TYPES: &'static [EthAbiTypeDesc] = &[T::DESC];
}

impl_eth_abi_return_tuple!(A a, B b);
impl_eth_abi_return_tuple!(A a, B b, C c);
impl_eth_abi_return_tuple!(A a, B b, C c, D d);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n, O o);
impl_eth_abi_return_tuple!(A a, B b, C c, D d, E e, F f, G g, H h, I i, J j, K k, L l, M m, N n, O o, P p);

impl EthAbiType for U256 {
    type SolType = sol_data::Uint<256>;

    const DESC: EthAbiTypeDesc = base_desc("uint256", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value)
    }
}

impl EthAbiType for U128 {
    type SolType = sol_data::Uint<128>;

    const DESC: EthAbiTypeDesc = base_desc("uint128", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.to::<u128>()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(Self::from_limbs([value as u64, (value >> 64) as u64]))
    }
}

impl EthAbiType for U64 {
    type SolType = sol_data::Uint<64>;

    const DESC: EthAbiTypeDesc = base_desc("uint64", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.to::<u64>()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(Self::from_limbs([value]))
    }
}

macro_rules! impl_eth_abi_uint {
    ($ty:ty, $bits:literal, $desc:literal) => {
        impl EthAbiType for $ty {
            type SolType = sol_data::Uint<$bits>;

            const DESC: EthAbiTypeDesc = base_desc($desc, false);

            fn into_sol(self) -> <Self::SolType as SolType>::RustType {
                self
            }

            fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
                Some(value)
            }
        }
    };
}

impl_eth_abi_uint!(u64, 64, "uint64");
impl_eth_abi_uint!(u32, 32, "uint32");
impl_eth_abi_uint!(u16, 16, "uint16");
impl_eth_abi_uint!(u8, 8, "uint8");

impl EthAbiType for bool {
    type SolType = sol_data::Bool;

    const DESC: EthAbiTypeDesc = base_desc("bool", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value)
    }
}

impl EthAbiType for Bytes {
    type SolType = sol_data::Bytes;

    const DESC: EthAbiTypeDesc = base_desc("bytes", true);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.to_vec().into()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(Bytes::copy_from_slice(value.as_ref()))
    }
}

impl EthAbiType for String {
    type SolType = sol_data::String;

    const DESC: EthAbiTypeDesc = base_desc("string", true);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value)
    }
}

impl EthAbiType for Address {
    type SolType = sol_data::Address;

    const DESC: EthAbiTypeDesc = base_desc("address", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value)
    }
}

impl EthAbiType for B256 {
    type SolType = sol_data::FixedBytes<32>;

    const DESC: EthAbiTypeDesc = base_desc("bytes32", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value)
    }
}

impl EthAbiType for LyquidID {
    type SolType = sol_data::Address;

    const DESC: EthAbiTypeDesc = base_desc("address", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.into()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(value.into())
    }
}

impl EthAbiType for RequiredLyquid {
    type SolType = sol_data::Address;

    const DESC: EthAbiTypeDesc = base_desc("address", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.0.into()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(Self(value.into()))
    }
}

impl EthAbiType for NodeID {
    type SolType = sol_data::FixedBytes<32>;

    const DESC: EthAbiTypeDesc = base_desc("bytes32", false);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        <[u8; 32]>::from(self).into()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        Some(NodeID::from(<[u8; 32]>::from(value)))
    }
}

impl<T: EthAbiType> EthAbiType for Vec<T> {
    type SolType = sol_data::Array<T::SolType>;

    const DESC: EthAbiTypeDesc = T::DESC.with_dim(None);

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.into_iter().map(T::into_sol).collect()
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        value.into_iter().map(T::from_sol).collect()
    }
}

impl<T: EthAbiType, const N: usize> EthAbiType for [T; N] {
    type SolType = sol_data::FixedArray<T::SolType, N>;

    const DESC: EthAbiTypeDesc = T::DESC.with_dim(Some(N as u32));

    fn into_sol(self) -> <Self::SolType as SolType>::RustType {
        self.map(T::into_sol)
    }

    fn from_sol(value: <Self::SolType as SolType>::RustType) -> Option<Self> {
        let mut out = Vec::with_capacity(N);
        for value in value {
            out.push(T::from_sol(value)?);
        }
        out.try_into().ok()
    }
}
