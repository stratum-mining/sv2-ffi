// What a server reads from the network, before and after the handshake:
//
// - mode 0: any act 1 from an initiator;
// - mode 1: after a real handshake, any bytes as the encrypted stream;
// - mode 2: after a real handshake, frames the input chooses (any header,
//   any payload), encrypted by the miner, maybe with one bit flipped on the
//   wire, read back in pieces the input chooses.
//
// Nothing may panic, the reader must make progress or stop, an intact
// stream must come back as one result per frame, and a decoded message
// must be of the type its frame said.
#![no_main]

mod miner;

use libfuzzer_sys::fuzz_target;
use miner::{authority, frame, Miner};
use sv2_ffi::*;

/// Feed `input` to the server `step` bytes at a time.  Every frame that
/// comes out goes to `seen`: its message type when it decoded, None when it
/// held no message the API returns.  Returns false once the session ended.
unsafe fn read_all(n: *mut Sv2FfiNoise, mut input: &[u8], step: usize, seen: &mut Vec<Option<u8>>) -> bool {
    while !input.is_empty() {
        let piece = input.len().min(step);
        let mut consumed = 0u32;
        let mut m = core::mem::MaybeUninit::<Sv2FfiMessage>::zeroed();
        let r = unsafe { sv2_ffi_noise_try_decode(n, input.as_ptr(), piece as u32, &mut consumed, m.as_mut_ptr()) };
        assert_ne!(r, SV2_FFI_ERR_INTERNAL);
        assert!(consumed as usize <= piece);
        match r {
            SV2_FFI_OK => seen.push(Some(unsafe { m.assume_init_ref() }.msg_type)),
            SV2_FFI_NEED_MORE => assert_eq!(consumed as usize, piece, "NEED_MORE left bytes behind"),
            _ if unsafe { sv2_ffi_noise_is_transport(n) } => seen.push(None),
            _ => return false,
        }
        if consumed == 0 {
            return true;
        }
        input = &input[consumed as usize..];
    }
    true
}

fuzz_target!(|data: &[u8]| {
    let (sk, pk) = authority();
    let [mode, step, flip_hi, flip_lo, rest @ ..] = data else {
        return;
    };
    let now = 1_700_000_000;
    let step = 1 + *step as usize * 3;
    unsafe {
        let server = sv2_ffi_noise_responder_new(pk.as_ptr(), sk.as_ptr(), 3600);
        assert!(!server.is_null());
        match mode % 3 {
            0 => {
                if rest.len() >= SV2_FFI_ACT1_SIZE {
                    let mut act2 = [0u8; SV2_FFI_ACT2_SIZE];
                    let r = sv2_ffi_noise_responder_step1(server, rest.as_ptr(), now, act2.as_mut_ptr());
                    assert_ne!(r, SV2_FFI_ERR_INTERNAL);
                }
            }
            1 => {
                let _miner = Miner::connect(server, pk, now);
                read_all(server, rest, step, &mut Vec::new());
            }
            _ => {
                let mut miner = Miner::connect(server, pk, now);
                // frames: 3 bytes of header choice (extension, type), one
                // length byte, then that many payload bytes
                let (mut sent, mut wire, mut input) = (Vec::new(), Vec::new(), rest);
                while input.len() >= 4 {
                    let len = (input[3] as usize * 23).min(input.len() - 4);
                    let ext = u16::from_le_bytes([input[0], input[1]]);
                    let f = frame(ext, input[2], &input[4..4 + len]);
                    input = &input[4 + len..];
                    wire.extend_from_slice(&miner.send(&f).unwrap());
                    sent.push(f[2]);
                }
                let flip = ((*flip_hi as usize) << 8) | *flip_lo as usize;
                let flipped = flip < wire.len() * 8 && *mode >= 128;
                if flipped {
                    wire[flip / 8] ^= 1 << (flip % 8);
                }
                let mut seen = Vec::new();
                let ok = read_all(server, &wire, step, &mut seen);
                if !flipped {
                    assert!(ok, "an intact stream failed");
                    assert_eq!(seen.len(), sent.len(), "an intact stream came back with other frames");
                } else {
                    // a flipped bit fails the tag of its piece; the frames
                    // before it came back
                    assert!(seen.len() <= sent.len());
                }
                for (got, sent) in seen.iter().zip(&sent) {
                    if let Some(t) = got {
                        assert_eq!(t, sent, "a message of another type than its frame");
                    }
                }
            }
        }
        sv2_ffi_noise_free(server);
    }
});
