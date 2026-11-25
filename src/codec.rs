// The encrypted transport through codec_sv2.
//
// A `Sv2FfiNoise` is one connection: a codec_sv2 handshake state that
// becomes the two halves of a transport state once the handshake completes,
// plus the crate's encoder and decoder.  The decoder owns the receive side
// reassembly (it reads the encrypted header, then the payload a chunk at a
// time) and the encoder the framing and the chunking on the way out.  The
// session takes a message record to send and hands out the record of each
// message received, so the frame header stays between the crates: this
// file moves bytes between the caller's buffers and the crate's, and keeps
// the last decoded frame for the record that points into it.
//
// As in noise_sv2, a responder makes a fresh static key when it is created
// and signs a certificate valid from `now` for `cert_validity_secs` at every
// handshake.  There is nothing to renew.  stratum-mining/stratum#2437 is
// the upstream request for a responder built from a static key and a
// pre-issued certificate; this API changes with it.

use core::time::Duration;

use codec_sv2::{
    Decrypted, EncodableFrame, Handshake, InitiatorSent, NoiseDecoder, NoiseEncoder, SerializedFrame,
    TransportDecryptState, TransportEncryptState, ENCRYPTED_SV2_FRAME_HEADER_SIZE, SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
};
use framing_sv2::SV2_FRAME_HEADER_SIZE;
use noise_sv2::{Initiator, Responder, AEAD_MAC_LEN};

use crate::ffi::{guard, input, obj, obj_mut, output, ret};
use crate::messages::{self, Sv2FfiMessage};
use crate::{
    SV2_FFI_ACT1_SIZE, SV2_FFI_ACT2_SIZE, SV2_FFI_ERR_CERT, SV2_FFI_ERR_CRYPTO, SV2_FFI_ERR_INTERNAL,
    SV2_FFI_ERR_INVALID, SV2_FFI_ERR_OVERFLOW, SV2_FFI_ERR_STATE, SV2_FFI_NEED_MORE, SV2_FFI_OK,
};

enum Role {
    Initiator(Handshake<Initiator>),
    InitiatorSent(Handshake<InitiatorSent>),
    Responder(Handshake<Responder>),
    Transport {
        encrypt: TransportEncryptState,
        // taken by the decoder for the duration of a decode round
        decrypt: Option<TransportDecryptState>,
    },
    // a failed handshake or AEAD step leaves the session unusable
    Dead,
}

/// One Noise session.  Opaque to C.
pub struct Sv2FfiNoise {
    role: Role,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
    // the frame of the last record sv2_ffi_noise_try_decode() handed out,
    // whose byte fields point into it
    frame: Option<SerializedFrame>,
}

impl Sv2FfiNoise {
    fn new(role: Role) -> Box<Self> {
        Box::new(Self {
            role,
            encoder: NoiseEncoder::new(),
            decoder: NoiseDecoder::new(),
            frame: None,
        })
    }

    fn kill(&mut self, code: i32) -> i32 {
        self.role = Role::Dead;
        code
    }
}

/// A plaintext frame already serialized, handed to the encoder as is.
struct Raw<'a>(&'a [u8]);

impl EncodableFrame for Raw<'_> {
    fn encoded_length(&self) -> usize {
        self.0.len()
    }

    fn encode_into(self, dst: &mut [u8]) -> Result<(), framing_sv2::Error> {
        dst.copy_from_slice(self.0);
        Ok(())
    }
}

/// Wire size of a plaintext frame of `frame_len` bytes, header included:
/// the encrypted header, then the payload in chunks, each with its tag.
fn wire_size(frame_len: usize) -> usize {
    let payload = frame_len.saturating_sub(SV2_FRAME_HEADER_SIZE);
    ENCRYPTED_SV2_FRAME_HEADER_SIZE + payload + payload.div_ceil(SV2_FRAME_PLAINTEXT_CHUNK_SIZE) * AEAD_MAC_LEN
}

/// Create a responder from the authority key pair (x-only public key and
/// secret key, 32 bytes each).  Each handshake signs a certificate valid
/// from its `now` for `cert_validity_secs`, which noise_sv2 checks with a
/// few seconds of leeway either side; 0 leaves only that leeway.  Returns
/// NULL when the keys do not match.  Free with `sv2_ffi_noise_free()`.
///
/// # Safety
/// `authority_pk` and `authority_sk` must each point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_responder_new(
    authority_pk: *const u8,
    authority_sk: *const u8,
    cert_validity_secs: u32,
) -> *mut Sv2FfiNoise {
    guard(core::ptr::null_mut(), || {
        // SAFETY: forwarded to the caller
        let (pk, sk) = match unsafe { (input(authority_pk, 32), input(authority_sk, 32)) } {
            (Ok(pk), Ok(sk)) => (pk, sk),
            _ => return core::ptr::null_mut(),
        };
        let (Ok(pk), Ok(sk)) = (<&[u8; 32]>::try_from(pk), <&[u8; 32]>::try_from(sk)) else {
            return core::ptr::null_mut();
        };
        match Responder::from_authority_kp(pk, sk, Duration::from_secs(cert_validity_secs as u64)) {
            Ok(r) => Box::into_raw(Sv2FfiNoise::new(Role::Responder(Handshake::responder(r)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Create an initiator that accepts only a responder whose certificate is
/// signed by `authority_pk` (32 bytes, x-only).  Returns NULL for NULL or
/// a key that is not a valid x-only point.  Free with
/// `sv2_ffi_noise_free()`.
///
/// # Safety
/// `authority_pk` must point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_initiator_new(authority_pk: *const u8) -> *mut Sv2FfiNoise {
    guard(core::ptr::null_mut(), || {
        if authority_pk.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: forwarded to the caller
        let Ok(pk) = (unsafe { input(authority_pk, 32) }) else {
            return core::ptr::null_mut();
        };
        let Ok(pk) = <[u8; 32]>::try_from(pk) else {
            return core::ptr::null_mut();
        };
        match Initiator::from_raw_k(pk) {
            Ok(i) => Box::into_raw(Sv2FfiNoise::new(Role::Initiator(Handshake::initiator(i)))),
            Err(_) => core::ptr::null_mut(),
        }
    })
}

/// Release a session, the keys it holds and the last frame it decoded.
/// NULL is ignored.
///
/// # Safety
/// `n` must be NULL or a pointer from one of the `_new` functions, not
/// freed before.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_free(n: *mut Sv2FfiNoise) {
    guard((), || {
        if !n.is_null() {
            // SAFETY: the pointer came from Box::into_raw
            drop(unsafe { Box::from_raw(n) });
        }
    })
}

/// Initiator: write act 1 (64 bytes) to send.
///
/// # Safety
/// `n` must be a live session and `out` must point at 64 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_initiator_step0(n: *mut Sv2FfiNoise, out: *mut u8) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, out) = unsafe { (obj_mut(n)?, output(out, SV2_FFI_ACT1_SIZE)?) };
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::Initiator(h) => match h.step_0() {
                    Ok((act1, next)) => {
                        out.copy_from_slice(act1.payload());
                        n.role = Role::InitiatorSent(next);
                        Ok(SV2_FFI_OK)
                    }
                    Err(_) => Err(SV2_FFI_ERR_CRYPTO),
                },
                other => {
                    n.role = other;
                    Err(SV2_FFI_ERR_STATE)
                }
            }
        })())
    })
}

/// Responder: consume act 1 (64 bytes) and write act 2 (234 bytes) to
/// send.  The certificate inside is valid from `now` (unix seconds).  On
/// success the session is in transport mode.
///
/// # Safety
/// `n` must be a live session, `act1` must point at 64 readable bytes and
/// `act2_out` at 234 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_responder_step1(
    n: *mut Sv2FfiNoise,
    act1: *const u8,
    now: u32,
    act2_out: *mut u8,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, act1, out) = unsafe {
                (
                    obj_mut(n)?,
                    input(act1, SV2_FFI_ACT1_SIZE)?,
                    output(act2_out, SV2_FFI_ACT2_SIZE)?,
                )
            };
            let mut theirs = [0u8; SV2_FFI_ACT1_SIZE];
            theirs.copy_from_slice(act1);
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::Responder(h) => match h.step_1_with_now_rng(theirs, now, &mut rand::thread_rng()) {
                    Ok((act2, transport)) => {
                        out.copy_from_slice(act2.payload());
                        let (encrypt, decrypt) = transport.split();
                        n.role = Role::Transport {
                            encrypt,
                            decrypt: Some(decrypt),
                        };
                        Ok(SV2_FFI_OK)
                    }
                    Err(_) => Err(SV2_FFI_ERR_CRYPTO),
                },
                other => {
                    n.role = other;
                    Err(SV2_FFI_ERR_STATE)
                }
            }
        })())
    })
}

/// Initiator: consume act 2 (234 bytes).  `now` (unix seconds) is checked
/// against the certificate's validity.  `SV2_FFI_ERR_CERT` means the
/// responder could not be authenticated with the pinned authority key at
/// `now`.
///
/// # Safety
/// `n` must be a live session and `act2` must point at 234 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_initiator_step2(n: *mut Sv2FfiNoise, act2: *const u8, now: u32) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, act2) = unsafe { (obj_mut(n)?, input(act2, SV2_FFI_ACT2_SIZE)?) };
            let mut msg = [0u8; SV2_FFI_ACT2_SIZE];
            msg.copy_from_slice(act2);
            match core::mem::replace(&mut n.role, Role::Dead) {
                Role::InitiatorSent(h) => match h.step_2_with_now(msg, now) {
                    Ok(transport) => {
                        let (encrypt, decrypt) = transport.split();
                        n.role = Role::Transport {
                            encrypt,
                            decrypt: Some(decrypt),
                        };
                        Ok(SV2_FFI_OK)
                    }
                    Err(codec_sv2::Error::NoiseSv2Error(noise_sv2::Error::InvalidCertificate(_))) => {
                        Err(SV2_FFI_ERR_CERT)
                    }
                    Err(codec_sv2::Error::NoiseSv2Error(noise_sv2::Error::Aead(_)))
                    | Err(codec_sv2::Error::AeadError(_)) => Err(SV2_FFI_ERR_CRYPTO),
                    Err(_) => Err(SV2_FFI_ERR_INVALID),
                },
                other => {
                    n.role = other;
                    Err(SV2_FFI_ERR_STATE)
                }
            }
        })())
    })
}

/// Whether the handshake has completed and messages can be exchanged:
/// false before that, and after a failure that ended the session.
///
/// # Safety
/// `n` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_is_transport(n: *const Sv2FfiNoise) -> bool {
    guard(false, || {
        // SAFETY: forwarded to the caller
        matches!(
            unsafe { n.as_ref() },
            Some(Sv2FfiNoise {
                role: Role::Transport { .. },
                ..
            })
        )
    })
}

/// The number of bytes `sv2_ffi_noise_encode()` writes for `m`, or
/// `SV2_FFI_ERR_INVALID` for a record it refuses.  The record is
/// serialized to tell, so a caller whose buffer is large enough for any
/// message it sends can skip this and handle `SV2_FFI_ERR_OVERFLOW`.
///
/// # Safety
/// `m` must point at a record whose byte fields are readable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_encoded_size(m: *const Sv2FfiMessage) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let len = unsafe { messages::frame_len(obj(m)?)? };
            Ok(wire_size(len) as i32)
        })())
    })
}

/// Encode the message in `m` and encrypt it into `out`, ready to send: the
/// message type and the channel_msg bit of its frame are the ones mining_sv2
/// or common_messages_sv2 assigns, and the payload goes in chunks of at most
/// 65519 bytes, each with its own tag.  Returns the bytes written,
/// `SV2_FFI_ERR_OVERFLOW` when `cap` is below `sv2_ffi_noise_encoded_size()`,
/// or `SV2_FFI_ERR_INVALID` for a field out of range (a `nominal_hash_rate`
/// that is negative or not finite among them) or a `msg_type` this API has
/// no record for.  None of these touch the session; a failure of the
/// encryption itself ends it.  Byte fields of `m` are read only during the
/// call.
///
/// # Safety
/// `n` must be a live session, `m` must point at a record whose byte fields
/// are readable, and `out` at `cap` writable bytes, not overlapping them.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_encode(
    n: *mut Sv2FfiNoise,
    m: *const Sv2FfiMessage,
    out: *mut u8,
    cap: u32,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (n, m, out) = unsafe { (obj_mut(n)?, obj(m)?, output(out, cap as usize)?) };
            let Role::Transport { encrypt, .. } = &mut n.role else {
                return Err(SV2_FFI_ERR_STATE);
            };
            // SAFETY: forwarded to the caller
            let plain = unsafe { messages::frame(m)? };
            let total = wire_size(plain.len());
            if total > out.len() {
                return Err(SV2_FFI_ERR_OVERFLOW);
            }
            match n.encoder.encode_transport(Raw(&plain), encrypt) {
                Ok(wire) => {
                    let wire: &[u8] = wire.as_ref();
                    if wire.len() != total {
                        return Err(n.kill(SV2_FFI_ERR_CRYPTO));
                    }
                    out[..total].copy_from_slice(wire);
                    Ok(total as i32)
                }
                Err(_) => Err(n.kill(SV2_FFI_ERR_CRYPTO)),
            }
        })())
    })
}

/// Decrypt and decode the next message from a byte stream.  Feed whatever
/// has arrived:
///
/// - `SV2_FFI_OK`: `*out` is the next message and `*consumed` input bytes
///   were used; the rest of the input belongs to the messages after it.
///   The record's byte fields point into the frame the session keeps, and
///   stay valid until the next `sv2_ffi_noise_try_decode()` on the session
///   or its `sv2_ffi_noise_free()`.
/// - `SV2_FFI_NEED_MORE`: all `in_len` bytes were used (the decoder keeps
///   them) and the caller should wait for more.
/// - `SV2_FFI_ERR_UNSUPPORTED`, `SV2_FFI_ERR_INVALID` or
///   `SV2_FFI_ERR_TRUNCATED` with `sv2_ffi_noise_is_transport()` still
///   true: a whole frame arrived, its last byte within the `*consumed` used,
///   but holds no message this API returns: one it has no record for (an
///   unknown type, an extension's messages, job declaration, template
///   distribution), which the caller may ignore, or one that does not
///   decode.  The session goes on with the next frame.
/// - `SV2_FFI_ERR_INVALID` for a NULL `n` or `out`, or a NULL `input_buf`
///   with `in_len` above 0, and `SV2_FFI_ERR_STATE` before the handshake is
///   done: nothing was used (`*consumed` is 0) and the session is as it was.
/// - any other negative code, or `SV2_FFI_ERR_STATE` once the session was
///   in transport: the session is over.
///
/// `*consumed` is written on every return; a NULL `consumed` is
/// `SV2_FFI_ERR_INVALID`.
///
/// Bytes in a frame after its message are left to parsers_sv2, which reads
/// them as the TLV fields of the extensions a connection negotiated; this
/// API negotiates none, so they are ignored.  The decoder takes a frame a
/// chunk at a time, so memory follows the bytes a peer actually sends; a
/// caller that wants to bound a frame counts `*consumed` across
/// `SV2_FFI_NEED_MORE` returns.
///
/// # Safety
/// `n` must be a live session, `input_buf` must point at `in_len` readable
/// bytes, and `consumed` and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_noise_try_decode(
    n: *mut Sv2FfiNoise,
    input_buf: *const u8,
    in_len: u32,
    consumed: *mut u32,
    out: *mut Sv2FfiMessage,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // `*consumed` first, so that every return sets it
            // SAFETY: forwarded to the caller
            let consumed = unsafe { obj_mut(consumed)? };
            *consumed = 0;
            // SAFETY: forwarded to the caller
            let (n, mut inp, out) = unsafe { (obj_mut(n)?, input(input_buf, in_len as usize)?, obj_mut(out)?) };
            let Role::Transport { decrypt, .. } = &mut n.role else {
                return Err(SV2_FFI_ERR_STATE);
            };
            // the bytes of the record handed out last go with their frame
            n.frame = None;
            loop {
                // The decoder asks for what it is missing, one chunk at most.
                let want = n.decoder.read_len();
                if want > 0 {
                    if inp.is_empty() {
                        return Ok(SV2_FFI_NEED_MORE);
                    }
                    let take = want.min(inp.len());
                    n.decoder.read_buf()[..take].copy_from_slice(&inp[..take]);
                    if n.decoder.advance(take).is_err() {
                        return Err(n.kill(SV2_FFI_ERR_INVALID));
                    }
                    inp = &inp[take..];
                    *consumed += take as u32;
                }
                let Some(state) = decrypt.take() else {
                    return Err(n.kill(SV2_FFI_ERR_STATE));
                };
                match n.decoder.next_transport_frame(state) {
                    Ok(Decrypted::Frame(frame, state)) => {
                        *decrypt = Some(state);
                        let frame = n.frame.insert(frame);
                        let header = frame.header();
                        // SAFETY: the payload is the session's, and stays
                        // where it is until the next decode
                        *out = unsafe { messages::decode(header, frame.payload())? };
                        return Ok(SV2_FFI_OK);
                    }
                    Ok(Decrypted::Incomplete(state)) => *decrypt = Some(state),
                    // the crate consumed the state: the nonce sequence is unusable
                    Err(codec_sv2::Error::AeadError(_)) => return Err(n.kill(SV2_FFI_ERR_CRYPTO)),
                    Err(_) => return Err(n.kill(SV2_FFI_ERR_INVALID)),
                }
            }
        })())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::*;
    use crate::{sv2_ffi_authority_keypair_generate, Sv2FfiBytes, SV2_FFI_ERR_TRUNCATED, SV2_FFI_ERR_UNSUPPORTED};

    fn pair() -> (*mut Sv2FfiNoise, *mut Sv2FfiNoise) {
        let (mut sk, mut pk) = ([0u8; 32], [0u8; 32]);
        unsafe {
            assert_eq!(
                sv2_ffi_authority_keypair_generate(sk.as_mut_ptr(), pk.as_mut_ptr()),
                SV2_FFI_OK
            );
            let r = sv2_ffi_noise_responder_new(pk.as_ptr(), sk.as_ptr(), 3600);
            let i = sv2_ffi_noise_initiator_new(pk.as_ptr());
            let (mut act1, mut act2) = ([0u8; SV2_FFI_ACT1_SIZE], [0u8; SV2_FFI_ACT2_SIZE]);
            assert_eq!(sv2_ffi_noise_initiator_step0(i, act1.as_mut_ptr()), SV2_FFI_OK);
            assert_eq!(
                sv2_ffi_noise_responder_step1(r, act1.as_ptr(), 1_760_000_000, act2.as_mut_ptr()),
                SV2_FFI_OK
            );
            assert_eq!(
                sv2_ffi_noise_initiator_step2(i, act2.as_ptr(), 1_760_000_000),
                SV2_FFI_OK
            );
            assert!(sv2_ffi_noise_is_transport(r) && sv2_ffi_noise_is_transport(i));
            (i, r)
        }
    }

    fn send(from: *mut Sv2FfiNoise, m: &Sv2FfiMessage) -> Vec<u8> {
        unsafe {
            let size = sv2_ffi_noise_encoded_size(m);
            assert!(size > 0, "size of type {:#x}: {size}", m.msg_type);
            let mut wire = vec![0u8; size as usize];
            let n = sv2_ffi_noise_encode(from, m, wire.as_mut_ptr(), wire.len() as u32);
            assert_eq!(n, size, "encode of type {:#x}", m.msg_type);
            wire
        }
    }

    // A frame the encoder would never write, encrypted as is.
    fn send_raw(from: *mut Sv2FfiNoise, frame: &[u8]) -> Vec<u8> {
        let n = unsafe { &mut *from };
        let Role::Transport { encrypt, .. } = &mut n.role else {
            panic!("not in transport mode");
        };
        let wire = n.encoder.encode_transport(Raw(frame), encrypt).unwrap();
        let wire: &[u8] = wire.as_ref();
        wire.to_vec()
    }

    /// Feed `wire` to `to` `step` bytes at a time until a call returns
    /// something other than `SV2_FFI_NEED_MORE`; returns that code and the
    /// bytes used.
    fn receive(to: *mut Sv2FfiNoise, wire: &[u8], step: usize, out: &mut Sv2FfiMessage) -> (i32, usize) {
        let mut pos = 0;
        loop {
            let piece = step.min(wire.len() - pos);
            let mut used = 0u32;
            let code = unsafe { sv2_ffi_noise_try_decode(to, wire[pos..].as_ptr(), piece as u32, &mut used, out) };
            pos += used as usize;
            if code != SV2_FFI_NEED_MORE {
                return (code, pos);
            }
            assert_eq!(used as usize, piece, "NEED_MORE takes every byte");
            if pos == wire.len() {
                return (code, pos);
            }
        }
    }

    fn empty() -> Sv2FfiMessage {
        // SAFETY: every member is plain data or a pointer, for which zero
        // is a value
        unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
    }

    fn job(prefix: &[u8], suffix: &[u8]) -> Sv2FfiMessage {
        Sv2FfiMessage {
            msg_type: SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB,
            u: Sv2FfiMessageUnion {
                new_extended_mining_job: Sv2FfiNewExtendedMiningJob {
                    channel_id: 5,
                    job_id: 7,
                    has_ntime_start: false,
                    ntime_start: 0,
                    version: 0x2000_0000,
                    version_rolling_allowed: true,
                    merkle_path_count: 0,
                    merkle_path: Sv2FfiBytes::EMPTY,
                    coinbase_tx_prefix: Sv2FfiBytes::from_slice(prefix),
                    coinbase_tx_suffix: Sv2FfiBytes::from_slice(suffix),
                },
            },
        }
    }

    // Messages of every size class go through, fed whole and a byte at a
    // time: one chunk, one just under a chunk's payload, and three chunks.
    #[test]
    fn messages_round_trip_across_chunk_boundaries() {
        let (i, r) = pair();
        let long_suffix = vec![2u8; 65535];
        for prefix_len in [0usize, 100, SV2_FRAME_PLAINTEXT_CHUNK_SIZE - 40, 65535] {
            let prefix: Vec<u8> = (0..prefix_len).map(|k| (k * 7) as u8).collect();
            let suffix = &long_suffix[..if prefix_len == 65535 { 65535 } else { 10 }];
            let m = job(&prefix, suffix);
            for step in [usize::MAX, 1] {
                let wire = send(i, &m);
                let mut back = empty();
                let (code, used) = receive(r, &wire, step, &mut back);
                assert_eq!(
                    (code, used),
                    (SV2_FFI_OK, wire.len()),
                    "prefix {prefix_len}, step {step}"
                );
                let j = unsafe { back.u.new_extended_mining_job };
                assert_eq!(unsafe { j.coinbase_tx_prefix.as_slice() }.unwrap(), &prefix[..]);
                assert_eq!(unsafe { j.coinbase_tx_suffix.as_slice() }.unwrap(), suffix);
            }
        }
        unsafe {
            sv2_ffi_noise_free(i);
            sv2_ffi_noise_free(r);
        }
    }

    // Encoding into a buffer that cannot hold the result must not use a
    // nonce: the next message still decrypts.
    #[test]
    fn a_refused_encode_does_not_desynchronise() {
        let (i, r) = pair();
        let m = job(&[1u8; 300], &[2u8; 10]);
        let mut small = [0u8; 100];
        let code = unsafe { sv2_ffi_noise_encode(i, &m, small.as_mut_ptr(), small.len() as u32) };
        assert_eq!(code, SV2_FFI_ERR_OVERFLOW);
        let wire = send(i, &m);
        let mut back = empty();
        assert_eq!(receive(r, &wire, usize::MAX, &mut back), (SV2_FFI_OK, wire.len()));
        unsafe {
            sv2_ffi_noise_free(i);
            sv2_ffi_noise_free(r);
        }
    }

    // A frame that decrypts but holds no message this API returns is
    // consumed and reported; the session goes on.
    #[test]
    fn an_undecodable_frame_does_not_end_the_session() {
        let (i, r) = pair();
        let mut back = empty();
        // an unknown message type, and a SetTarget cut short
        for (frame, code) in [
            (vec![0, 0, 0x7f, 1, 0, 0, 9], SV2_FFI_ERR_UNSUPPORTED),
            (vec![0, 0x80, 0x21, 4, 0, 0, 1, 0, 0, 0], SV2_FFI_ERR_TRUNCATED),
        ] {
            let wire = send_raw(i, &frame);
            assert_eq!(receive(r, &wire, 3, &mut back), (code, wire.len()));
            assert!(unsafe { sv2_ffi_noise_is_transport(r) });
        }
        let m = job(&[1u8; 30], &[2u8; 10]);
        let wire = send(i, &m);
        assert_eq!(receive(r, &wire, usize::MAX, &mut back), (SV2_FFI_OK, wire.len()));
        assert_eq!(back.msg_type, SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB);
        unsafe {
            sv2_ffi_noise_free(i);
            sv2_ffi_noise_free(r);
        }
    }

    // A flipped bit fails the tag and ends the session; nothing works on it
    // after that.
    #[test]
    fn a_tampered_frame_ends_the_session() {
        let (i, r) = pair();
        let m = job(&[1u8; 30], &[2u8; 10]);
        let mut wire = send(i, &m);
        *wire.last_mut().unwrap() ^= 1;
        let mut back = empty();
        assert_eq!(receive(r, &wire, usize::MAX, &mut back).0, SV2_FFI_ERR_CRYPTO);
        assert!(!unsafe { sv2_ffi_noise_is_transport(r) });
        let mut used = 0;
        let mut out = [0u8; 256];
        unsafe {
            assert_eq!(
                sv2_ffi_noise_try_decode(r, wire.as_ptr(), wire.len() as u32, &mut used, &mut back),
                SV2_FFI_ERR_STATE
            );
            assert_eq!(sv2_ffi_noise_encode(r, &m, out.as_mut_ptr(), 256), SV2_FFI_ERR_STATE);
            sv2_ffi_noise_free(i);
            sv2_ffi_noise_free(r);
        }
    }
}
