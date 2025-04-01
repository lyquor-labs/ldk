use crate::runtime::ethabi::EthAbiTypeDesc;

pub const CATEGORY_NETWORK: u8 = 0;
pub const CATEGORY_INSTANCE: u8 = 1;

pub const INFO_SECTION: &str = "lyquor.method.info";
pub const INFO_VERSION: u8 = 1;

pub const EXPORT_SECTION: &str = "lyquor.method.export.eth";
pub const EXPORT_VERSION: u8 = 1;

const fn write_u16(out: &mut [u8], idx: &mut usize, val: u16) {
    out[*idx] = (val >> 8) as u8;
    out[*idx + 1] = (val & 0xff) as u8;
    *idx += 2;
}

const fn write_bytes(out: &mut [u8], idx: &mut usize, bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() {
        out[*idx + i] = bytes[i];
        i += 1;
    }
    *idx += bytes.len();
}

pub const fn info_len(group: &str, method: &str) -> usize {
    // version + category + mutable + group_len + method_len
    1 + 1 + 1 + 2 + 2 + group.len() + method.len()
}

pub const fn info_encode<const LEN: usize>(category: u8, mutable: bool, group: &str, method: &str) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    let mut idx = 0;
    out[idx] = INFO_VERSION;
    idx += 1;
    out[idx] = category;
    idx += 1;
    out[idx] = if mutable { 1 } else { 0 };
    idx += 1;
    write_u16(&mut out, &mut idx, group.len() as u16);
    write_u16(&mut out, &mut idx, method.len() as u16);
    write_bytes(&mut out, &mut idx, group.as_bytes());
    write_bytes(&mut out, &mut idx, method.as_bytes());
    out
}

const fn needs_location(desc: EthAbiTypeDesc) -> bool {
    if desc.is_dynamic {
        return true;
    }
    let mut i = 0usize;
    while i < desc.dims_len as usize {
        if desc.dims[i].is_none() {
            return true;
        }
        i += 1;
    }
    false
}

pub const fn export_len(group: &str, method: &str, params: &[EthAbiTypeDesc], returns: &[EthAbiTypeDesc]) -> usize {
    let mut len = 0;
    // version + category + mutable + param_count + return_count + group_len + method_len
    len += 1 + 1 + 1 + 1 + 1 + 2 + 2;
    len += group.len();
    len += method.len();

    let mut i = 0;
    while i < params.len() {
        len += 2 + params[i].len() + 1;
        i += 1;
    }

    i = 0;
    while i < returns.len() {
        len += 2 + returns[i].len() + 1;
        i += 1;
    }
    len
}

pub const fn export_encode<const LEN: usize>(
    category: u8, mutable: bool, group: &str, method: &str, params: &[EthAbiTypeDesc], returns: &[EthAbiTypeDesc],
) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    let mut idx = 0;
    out[idx] = EXPORT_VERSION;
    idx += 1;
    out[idx] = category;
    idx += 1;
    out[idx] = if mutable { 1 } else { 0 };
    idx += 1;
    out[idx] = params.len() as u8;
    idx += 1;
    out[idx] = returns.len() as u8;
    idx += 1;

    write_u16(&mut out, &mut idx, group.len() as u16);
    write_u16(&mut out, &mut idx, method.len() as u16);
    write_bytes(&mut out, &mut idx, group.as_bytes());
    write_bytes(&mut out, &mut idx, method.as_bytes());

    let mut i = 0;
    while i < params.len() {
        let ty_len = params[i].len();
        write_u16(&mut out, &mut idx, ty_len as u16);
        write_type(&mut out, &mut idx, params[i]);
        out[idx] = if needs_location(params[i]) { 1 } else { 0 };
        idx += 1;
        i += 1;
    }

    i = 0;
    while i < returns.len() {
        let ty_len = returns[i].len();
        write_u16(&mut out, &mut idx, ty_len as u16);
        write_type(&mut out, &mut idx, returns[i]);
        out[idx] = if needs_location(returns[i]) { 1 } else { 0 };
        idx += 1;
        i += 1;
    }

    out
}

const fn write_type(out: &mut [u8], idx: &mut usize, desc: EthAbiTypeDesc) {
    write_bytes(out, idx, desc.base.as_bytes());
    let mut i = 0usize;
    while i < desc.dims_len as usize {
        match desc.dims[i] {
            Some(val) => {
                out[*idx] = b'[';
                *idx += 1;
                write_u32(out, idx, val);
                out[*idx] = b']';
                *idx += 1;
            }
            None => {
                out[*idx] = b'[';
                out[*idx + 1] = b']';
                *idx += 2;
            }
        }
        i += 1;
    }
}

const fn write_u32(out: &mut [u8], idx: &mut usize, mut val: u32) {
    let mut buf = [0u8; 10];
    let mut len = 0usize;
    loop {
        buf[len] = (val % 10) as u8 + b'0';
        len += 1;
        val /= 10;
        if val == 0 {
            break;
        }
    }

    let mut i = 0usize;
    while i < len {
        out[*idx + i] = buf[len - 1 - i];
        i += 1;
    }
    *idx += len;
}
