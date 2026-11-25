//! sv2_ffi: a C API over the Stratum V2 Reference Implementation crates.
//!
//! For C programs that speak Stratum V2 with SRI's own code underneath:
//! the first one is DATUM Gateway, whose SV2 server is plain C.  The API is
//! cut to what a pool-side SV2 server needs today and laid out the way
//! the UniFFI crate of sv2-uniffi is:
//!
//! - `codec`: one Noise session per connection.  The handshake as responder
//!   (and as initiator, for tests and benchmarks) and the encrypted
//!   transport run through `codec_sv2`, which owns the framing, the
//!   chunking and the receive side reassembly; the authority key and
//!   certificate come from `noise_sv2`.  The session takes and hands out
//!   whole messages: a caller never sees a frame header.
//! - `messages`: the common and mining messages as plain C records, and the
//!   field-by-field conversions between them and the crates' structs.
//!   Which message a frame holds is decided by `parsers_sv2`, SRI's own
//!   dispatcher, and the message type and channel_msg bit a record goes
//!   out with by the subprotocol crates.
//! - `keys`: the authority key and its base58 text form.
//! - `channels`: server-side mining channels through `channels_sv2`: an
//!   extranonce allocator, and extended and standard channels that take
//!   their jobs as the bytes the server sends, validate the shares and keep
//!   the share accounting.
//!
//! Memory rules, which hold for every function here:
//!
//! - Buffers are owned by the caller.  An encoder writes into a caller
//!   buffer of a given capacity.
//! - A decoded message's variable length fields (`Sv2FfiBytes`) point into
//!   the frame the session decoded it from, which the session keeps until
//!   its next decode.
//! - The Rust allocations a caller holds are the objects of the `_new()`
//!   functions, each released with its `_free()`: a `Sv2FfiNoise` per
//!   connection, and in `channels` an allocator and a channel object per
//!   channel, which keeps the jobs it was given.  The crates allocate
//!   internally while they work; nothing else outlives a call.
//!
//! Every function returns `SV2_FFI_OK` (0), a positive byte count where the
//! documentation says so, or one of the negative `SV2_FFI_ERR_*` codes.  The
//! values are part of the API: a caller can store and compare them.
//!
//! No panic leaves the library: every exported function runs its body
//! under `catch_unwind` and reports a panic as `SV2_FFI_ERR_INTERNAL`
//! (NULL for a constructor), so one bad input on one connection cannot
//! take a server's other connections down with it.

#![deny(unsafe_op_in_unsafe_fn)]

mod channels;
mod codec;
mod ffi;
mod keys;
mod messages;

pub use channels::*;
pub use codec::*;
pub use ffi::Sv2FfiBytes;
pub use keys::*;
pub use messages::*;

// The header lets a caller move an object to another thread between calls,
// which needs every object a `_new()` hands out to be Send.
const _: () = {
    const fn send<T: Send>() {}
    send::<Sv2FfiNoise>();
    send::<Sv2FfiExtranonceAllocator>();
    send::<Sv2FfiExtendedChannel>();
    send::<Sv2FfiStandardChannel>();
};

/// Success
pub const SV2_FFI_OK: i32 = 0;
/// `sv2_ffi_noise_try_decode()`: more input is needed
pub const SV2_FFI_NEED_MORE: i32 = 1;
/// A frame ended before the message it holds did
pub const SV2_FFI_ERR_TRUNCATED: i32 = -1;
/// Output buffer too small
pub const SV2_FFI_ERR_OVERFLOW: i32 = -2;
/// Malformed or out of spec value, or a NULL argument
pub const SV2_FFI_ERR_INVALID: i32 = -3;
/// AEAD, ECDH or signature failure
pub const SV2_FFI_ERR_CRYPTO: i32 = -4;
/// The call does not fit the session's state: a handshake step out of
/// order, a message before the handshake completed, or a session a failure
/// ended
pub const SV2_FFI_ERR_STATE: i32 = -5;
/// The responder's certificate is not signed by the pinned authority key,
/// or `now` is outside its validity
pub const SV2_FFI_ERR_CERT: i32 = -7;
/// A well-formed frame of a message or extension this API has no record for
pub const SV2_FFI_ERR_UNSUPPORTED: i32 = -9;
/// A bug: the call panicked inside the library or the crates under it.  The
/// object it was made on may be half updated and must be freed, not used
/// again; anything else the caller holds is unaffected.  Functions that
/// return a pointer return NULL instead, and those that return nothing
/// return.
pub const SV2_FFI_ERR_INTERNAL: i32 = -10;

/// Handshake act 1 (initiator to responder): ElligatorSwift ephemeral key
pub const SV2_FFI_ACT1_SIZE: usize = 64;
/// Handshake act 2 (responder to initiator): e, encrypted s, encrypted certificate
pub const SV2_FFI_ACT2_SIZE: usize = 234;
/// Size of the base58 text form of an authority public key, NUL included
pub const SV2_FFI_AUTHORITY_BASE58_MAX: usize = 64;

// cbindgen only sees literals, so tie each one to the crate it comes from.
const _: () = {
    assert!(SV2_FFI_ACT1_SIZE == noise_sv2::ELLSWIFT_ENCODING_SIZE);
    assert!(SV2_FFI_ACT2_SIZE == noise_sv2::INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE);
};
