use std::string::String;

use alloy_dyn_abi::{DynSolType, DynSolValue};

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

pub fn dyn_sol_type(desc: EthAbiTypeDesc) -> Option<DynSolType> {
    let mut ty = base_dyn_sol(desc.base)?;
    let mut i = 0usize;
    while i < desc.dims_len as usize {
        match desc.dims[i] {
            Some(len) => ty = DynSolType::FixedArray(Box::new(ty), len as usize),
            None => ty = DynSolType::Array(Box::new(ty)),
        }
        i += 1;
    }
    Some(ty)
}

fn base_dyn_sol(base: &str) -> Option<DynSolType> {
    match base {
        "bool" => Some(DynSolType::Bool),
        "address" => Some(DynSolType::Address),
        "string" => Some(DynSolType::String),
        "bytes" => Some(DynSolType::Bytes),
        _ => {
            if let Some(bits) = base.strip_prefix("uint") {
                if let Ok(bits) = bits.parse::<usize>() {
                    return Some(DynSolType::Uint(bits));
                }
            }
            if let Some(bits) = base.strip_prefix("int") {
                if let Ok(bits) = bits.parse::<usize>() {
                    return Some(DynSolType::Int(bits));
                }
            }
            if let Some(bytes) = base.strip_prefix("bytes") {
                if let Ok(len) = bytes.parse::<usize>() {
                    return Some(DynSolType::FixedBytes(len));
                }
            }
            None
        }
    }
}

pub trait EthAbiValue {
    fn decode(val: DynSolValue) -> Option<Self>
    where
        Self: Sized;
    fn encode(self) -> DynSolValue;
}

pub trait EthAbiReturnValue {
    fn encode_return(self) -> Vec<DynSolValue>;
}

pub trait EthAbiType: EthAbiValue {
    const DESC: EthAbiTypeDesc;
}

pub trait EthAbiReturn: EthAbiReturnValue {
    const COUNT: usize;
    const TYPES: &'static [EthAbiTypeDesc];
}

impl EthAbiReturnValue for () {
    fn encode_return(self) -> Vec<DynSolValue> {
        Vec::new()
    }
}

impl<T: EthAbiValue> EthAbiReturnValue for T {
    fn encode_return(self) -> Vec<DynSolValue> {
        vec![self.encode()]
    }
}

impl<A: EthAbiValue, B: EthAbiValue> EthAbiReturnValue for (A, B) {
    fn encode_return(self) -> Vec<DynSolValue> {
        vec![self.0.encode(), self.1.encode()]
    }
}

impl<A: EthAbiValue, B: EthAbiValue, C: EthAbiValue> EthAbiReturnValue for (A, B, C) {
    fn encode_return(self) -> Vec<DynSolValue> {
        vec![self.0.encode(), self.1.encode(), self.2.encode()]
    }
}

impl<A: EthAbiValue, B: EthAbiValue, C: EthAbiValue, D: EthAbiValue> EthAbiReturnValue for (A, B, C, D) {
    fn encode_return(self) -> Vec<DynSolValue> {
        vec![self.0.encode(), self.1.encode(), self.2.encode(), self.3.encode()]
    }
}

impl<A: EthAbiValue, B: EthAbiValue, C: EthAbiValue, D: EthAbiValue, E: EthAbiValue> EthAbiReturnValue
    for (A, B, C, D, E)
{
    fn encode_return(self) -> Vec<DynSolValue> {
        vec![
            self.0.encode(),
            self.1.encode(),
            self.2.encode(),
            self.3.encode(),
            self.4.encode(),
        ]
    }
}

impl EthAbiReturn for () {
    const COUNT: usize = 0;
    const TYPES: &'static [EthAbiTypeDesc] = &[];
}

impl<T: EthAbiType> EthAbiReturn for T {
    const COUNT: usize = 1;
    const TYPES: &'static [EthAbiTypeDesc] = &[T::DESC];
}

impl<A: EthAbiType, B: EthAbiType> EthAbiReturn for (A, B) {
    const COUNT: usize = 2;
    const TYPES: &'static [EthAbiTypeDesc] = &[A::DESC, B::DESC];
}

impl<A: EthAbiType, B: EthAbiType, C: EthAbiType> EthAbiReturn for (A, B, C) {
    const COUNT: usize = 3;
    const TYPES: &'static [EthAbiTypeDesc] = &[A::DESC, B::DESC, C::DESC];
}

impl<A: EthAbiType, B: EthAbiType, C: EthAbiType, D: EthAbiType> EthAbiReturn for (A, B, C, D) {
    const COUNT: usize = 4;
    const TYPES: &'static [EthAbiTypeDesc] = &[A::DESC, B::DESC, C::DESC, D::DESC];
}

impl<A: EthAbiType, B: EthAbiType, C: EthAbiType, D: EthAbiType, E: EthAbiType> EthAbiReturn for (A, B, C, D, E) {
    const COUNT: usize = 5;
    const TYPES: &'static [EthAbiTypeDesc] = &[A::DESC, B::DESC, C::DESC, D::DESC, E::DESC];
}

impl EthAbiValue for U256 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 256) => Some(i),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self, 256)
    }
}

impl EthAbiType for U256 {
    const DESC: EthAbiTypeDesc = base_desc("uint256", false);
}

impl EthAbiValue for U128 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 128) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self.to(), 128)
    }
}

impl EthAbiType for U128 {
    const DESC: EthAbiTypeDesc = base_desc("uint128", false);
}

impl EthAbiValue for U64 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 64) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(self.to(), 64)
    }
}

impl EthAbiType for U64 {
    const DESC: EthAbiTypeDesc = base_desc("uint64", false);
}

impl EthAbiValue for u64 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 64) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(U256::from_limbs([self as u64, 0, 0, 0]), 64)
    }
}

impl EthAbiType for u64 {
    const DESC: EthAbiTypeDesc = base_desc("uint64", false);
}

impl EthAbiValue for u32 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 32) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(U256::from_limbs([self as u64, 0, 0, 0]), 32)
    }
}

impl EthAbiType for u32 {
    const DESC: EthAbiTypeDesc = base_desc("uint32", false);
}

impl EthAbiValue for u16 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 16) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(U256::from_limbs([self as u64, 0, 0, 0]), 16)
    }
}

impl EthAbiType for u16 {
    const DESC: EthAbiTypeDesc = base_desc("uint16", false);
}

impl EthAbiValue for u8 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Uint(i, 8) => Some(i.to()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Uint(U256::from_limbs([self as u64, 0, 0, 0]), 8)
    }
}

impl EthAbiType for u8 {
    const DESC: EthAbiTypeDesc = base_desc("uint8", false);
}

impl EthAbiValue for bool {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Bool(self)
    }
}

impl EthAbiType for bool {
    const DESC: EthAbiTypeDesc = base_desc("bool", false);
}

impl EthAbiValue for Bytes {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Bytes(b) => Some(b.into()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Bytes(self.to_vec().into())
    }
}

impl EthAbiType for Bytes {
    const DESC: EthAbiTypeDesc = base_desc("bytes", true);
}

impl EthAbiValue for String {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::String(s) => Some(s.into()),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::String(self.into())
    }
}

impl EthAbiType for String {
    const DESC: EthAbiTypeDesc = base_desc("string", true);
}

impl EthAbiValue for Address {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(a),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self)
    }
}

impl EthAbiType for Address {
    const DESC: EthAbiTypeDesc = base_desc("address", false);
}

impl EthAbiValue for B256 {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::FixedBytes(v, 32) => Some(v),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::FixedBytes(self, 32)
    }
}

impl EthAbiType for B256 {
    const DESC: EthAbiTypeDesc = base_desc("bytes32", false);
}

impl EthAbiValue for LyquidID {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(Self(a.0.into())),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self.0.into())
    }
}

impl EthAbiType for LyquidID {
    const DESC: EthAbiTypeDesc = base_desc("address", false);
}

impl EthAbiValue for RequiredLyquid {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Address(a) => Some(Self(a.0.0.into())),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Address(self.0.0.into())
    }
}

impl EthAbiType for RequiredLyquid {
    const DESC: EthAbiTypeDesc = base_desc("address", false);
}

impl EthAbiValue for NodeID {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::FixedBytes(v, 32) => {
                let arr: [u8; 32] = v.as_slice().try_into().ok()?;
                Some(NodeID::from(arr))
            }
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::FixedBytes(<[u8; 32]>::from(self).into(), 32)
    }
}

impl EthAbiType for NodeID {
    const DESC: EthAbiTypeDesc = base_desc("bytes32", false);
}

impl<T: EthAbiValue> EthAbiValue for Option<T> {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Array(v) => match v.len() {
                0 => Some(None),
                1 => T::decode(v.into_iter().next()?).map(Some),
                _ => None,
            },
            DynSolValue::FixedArray(v) => match v.len() {
                0 => Some(None),
                1 => T::decode(v.into_iter().next()?).map(Some),
                _ => None,
            },
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        match self {
            None => DynSolValue::Array(Vec::new()),
            Some(value) => DynSolValue::Array(vec![value.encode()]),
        }
    }
}

impl<T: EthAbiValue> EthAbiValue for Vec<T> {
    fn decode(val: DynSolValue) -> Option<Self> {
        match val {
            DynSolValue::Array(v) => v.into_iter().map(T::decode).collect(),
            _ => None,
        }
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::Array(self.into_iter().map(T::encode).collect())
    }
}

impl<T: EthAbiType> EthAbiType for Vec<T> {
    const DESC: EthAbiTypeDesc = T::DESC.with_dim(None);
}

impl<T: EthAbiValue, const N: usize> EthAbiValue for [T; N] {
    fn decode(val: DynSolValue) -> Option<Self> {
        let values = match val {
            DynSolValue::FixedArray(v) => v,
            DynSolValue::Array(v) => v,
            _ => return None,
        };

        if values.len() != N {
            return None;
        }

        let mut out = Vec::with_capacity(N);
        for value in values {
            out.push(T::decode(value)?);
        }

        out.try_into().ok()
    }

    fn encode(self) -> DynSolValue {
        DynSolValue::FixedArray(self.into_iter().map(T::encode).collect())
    }
}

impl<T: EthAbiType, const N: usize> EthAbiType for [T; N] {
    const DESC: EthAbiTypeDesc = T::DESC.with_dim(Some(N as u32));
}
