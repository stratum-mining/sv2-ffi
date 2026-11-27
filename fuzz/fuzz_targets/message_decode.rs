// A frame with any header fields and payload, sent by a miner over a real
// handshake and decoded by the server's session; for what decodes, the
// server's encoder on the record it gave back: re-encoding must work, but
// for the two cases named below, and what it wrote must decode again.
#![no_main]

mod miner;

use libfuzzer_sys::fuzz_target;
use miner::{authority, frame, Miner};
use sv2_ffi::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (sk, pk) = authority();
    let now = 1_700_000_000;
    let extension_type = u16::from_le_bytes([data[0], data[1]]);
    let msg_type = data[2];
    unsafe {
        let server = sv2_ffi_noise_responder_new(pk.as_ptr(), sk.as_ptr(), 3600);
        let mut miner = Miner::connect(server, pk, now);
        let wire = miner.send(&frame(extension_type, msg_type, &data[3..])).unwrap();
        let mut m = core::mem::MaybeUninit::<Sv2FfiMessage>::zeroed();
        let mut consumed = 0u32;
        let r = sv2_ffi_noise_try_decode(server, wire.as_ptr(), wire.len() as u32, &mut consumed, m.as_mut_ptr());
        assert_ne!(r, SV2_FFI_ERR_INTERNAL);
        // whatever the frame held, it was one frame, and an intact one
        assert_eq!(consumed as usize, wire.len());
        assert!(
            sv2_ffi_noise_is_transport(server),
            "an intact frame ended the session: {r}"
        );
        if r == SV2_FFI_OK {
            reencode(server, &mut miner, m.assume_init_ref(), msg_type);
        }
        sv2_ffi_noise_free(server);
    }
});

unsafe fn reencode(server: *mut Sv2FfiNoise, miner: &mut Miner, m: &Sv2FfiMessage, msg_type: u8) {
    unsafe {
        let size = sv2_ffi_noise_encoded_size(m);
        assert_ne!(size, SV2_FFI_ERR_INTERNAL);
        // A decoded record re-encodes, with two exceptions: a SetupConnection
        // carrying a protocol the crates have no value for (decoded on
        // purpose, so a role can answer it with SetupConnection.Error), and
        // a nominal_hash_rate that is negative or not finite, which
        // binary_sv2 decodes but does not serialize.
        if size < 0 {
            assert_eq!(size, SV2_FFI_ERR_INVALID);
            // SAFETY: the member read is the one msg_type names
            let rate = match msg_type {
                SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL => Some(m.u.open_standard_mining_channel.nominal_hash_rate),
                SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL => Some(m.u.open_extended_mining_channel.nominal_hash_rate),
                SV2_FFI_MSG_UPDATE_CHANNEL => Some(m.u.update_channel.nominal_hash_rate),
                _ => None,
            };
            match rate {
                Some(rate) => assert!(!rate.is_finite() || rate.is_sign_negative(), "{rate} does not encode"),
                None => assert_eq!(msg_type, SV2_FFI_MSG_SETUP_CONNECTION),
            }
            return;
        }
        let mut out = vec![0u8; size as usize];
        let n = sv2_ffi_noise_encode(server, m, out.as_mut_ptr(), out.len() as u32);
        assert_eq!(n, size, "encode wrote other than its size");
        // the miner reads the frame and sends it back as it came
        let plain = miner.receive(&out);
        let wire = miner.send(&plain).unwrap();
        let mut again = core::mem::MaybeUninit::<Sv2FfiMessage>::zeroed();
        let mut consumed = 0u32;
        let r = sv2_ffi_noise_try_decode(
            server,
            wire.as_ptr(),
            wire.len() as u32,
            &mut consumed,
            again.as_mut_ptr(),
        );
        assert_eq!(r, SV2_FFI_OK, "a frame the encoder wrote does not decode");
        assert_eq!(again.assume_init_ref().msg_type, msg_type);
    }
}
