//! WASM guest-test support for Lyquid crates.
//!
//! Add this crate as a dev-dependency and place guest tests behind Rust's normal
//! `#[cfg(test)]` target selection:
//!
//! ```toml
//! [dev-dependencies]
//! lyquid-test = "0.5.1-dev"
//! ```
//!
//! ```ignore
//! #[cfg(test)]
//! mod tests {
//!     #[lyquid_test::test]
//!     fn builds_a_value() {
//!         assert_eq!(String::from("guest"), "guest");
//!     }
//! }
//! ```
//!
//! Tests may return either `()` or [`lyquid::LyquidResult<()>`]. Place `#[ignore]`
//! after `#[lyquid_test::test]` so it is recorded in guest metadata instead of being
//! interpreted by Rust's native test harness.

/// Marks a synchronous zero-argument function as a discoverable WASM guest test.
pub use lyquid_proc::guest_test as test;

/// Implementation details used by the generated guest-test wrapper.
#[doc(hidden)]
pub mod __private {
    /// Version tag for guest-test descriptors.
    pub const TEST_INFO_VERSION: u8 = 1;
    /// Guest-test descriptor flag indicating an ignored test.
    pub const TEST_INFO_IGNORED: u8 = 0x1;

    const fn write_u16(out: &mut [u8], idx: &mut usize, val: u16) {
        out[*idx] = (val >> 8) as u8;
        out[*idx + 1] = (val & 0xff) as u8;
        *idx += 2;
    }

    const fn write_u32(out: &mut [u8], idx: &mut usize, val: u32) {
        out[*idx] = (val >> 24) as u8;
        out[*idx + 1] = ((val >> 16) & 0xff) as u8;
        out[*idx + 2] = ((val >> 8) & 0xff) as u8;
        out[*idx + 3] = (val & 0xff) as u8;
        *idx += 4;
    }

    const fn write_bytes(out: &mut [u8], idx: &mut usize, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            out[*idx + i] = bytes[i];
            i += 1;
        }
        *idx += bytes.len();
    }

    /// Returns the encoded byte length for a guest-test descriptor.
    pub const fn test_info_len(name: &str, export: &str, file: &str) -> usize {
        // version + flags + name_len + export_len + file_len + line + column
        1 + 1 + 2 + 2 + 2 + 4 + 4 + name.len() + export.len() + file.len()
    }

    /// Encodes a guest-test descriptor into a fixed-size WASM section payload.
    pub const fn test_info_encode<const LEN: usize>(
        name: &str, export: &str, ignored: bool, file: &str, line: u32, column: u32,
    ) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        let mut idx = 0;
        out[idx] = TEST_INFO_VERSION;
        idx += 1;
        out[idx] = if ignored { TEST_INFO_IGNORED } else { 0 };
        idx += 1;
        write_u16(&mut out, &mut idx, name.len() as u16);
        write_u16(&mut out, &mut idx, export.len() as u16);
        write_u16(&mut out, &mut idx, file.len() as u16);
        write_u32(&mut out, &mut idx, line);
        write_u32(&mut out, &mut idx, column);
        write_bytes(&mut out, &mut idx, name.as_bytes());
        write_bytes(&mut out, &mut idx, export.as_bytes());
        write_bytes(&mut out, &mut idx, file.as_bytes());
        out
    }

    /// Conversion accepted by generated guest-test wrappers.
    pub trait GuestTestTermination {
        fn into_result(self) -> lyquid::LyquidResult<()>;
    }

    impl GuestTestTermination for () {
        fn into_result(self) -> lyquid::LyquidResult<()> {
            Ok(())
        }
    }

    impl GuestTestTermination for lyquid::LyquidResult<()> {
        fn into_result(self) -> lyquid::LyquidResult<()> {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::__private::{GuestTestTermination, test_info_encode, test_info_len};

    #[test]
    fn encodes_guest_test_metadata() {
        const NAME: &str = "fixture::builds_a_value";
        const EXPORT: &str = "__lyquid_test_1234";
        const FILE: &str = "src/lib.rs";
        const LEN: usize = test_info_len(NAME, EXPORT, FILE);
        const ENCODED: [u8; LEN] = test_info_encode::<LEN>(NAME, EXPORT, true, FILE, 42, 7);

        assert_eq!(ENCODED[0], 1);
        assert_eq!(ENCODED[1], 1);
        assert_eq!(u16::from_be_bytes([ENCODED[2], ENCODED[3]]) as usize, NAME.len());
        assert_eq!(u32::from_be_bytes(ENCODED[8..12].try_into().unwrap()), 42);
        assert_eq!(u32::from_be_bytes(ENCODED[12..16].try_into().unwrap()), 7);
        assert!(ENCODED.ends_with(FILE.as_bytes()));
    }

    #[test]
    fn converts_supported_test_returns() {
        assert!(GuestTestTermination::into_result(()).is_ok());

        let error = lyquid::LyquidError::LyquidRuntime("failure".to_owned());
        let result = GuestTestTermination::into_result(Err(error));
        assert!(matches!(result, Err(lyquid::LyquidError::LyquidRuntime(message)) if message == "failure"));
    }
}
