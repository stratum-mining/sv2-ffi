//! An extended server channel:
//! `channels_sv2::server::extended::ExtendedChannel`.

use binary_sv2::B032Owned;
use channels_sv2::server::error::ExtendedChannelError;
use channels_sv2::server::extended::ExtendedChannel;
use channels_sv2::server::jobs::error::JobFactoryError;
use mining_sv2::SubmitSharesExtendedOwned;

use crate::channels::server::{accounting, chain_tip, hash_out, le_target, prebuilt, share_status, user_identity};
use crate::channels::{
    alloc_err, Sv2FfiChannelOpen, Sv2FfiExtranonceAllocator, Sv2FfiPrebuiltJob, Sv2FfiShareAccounting,
    SV2_FFI_ERR_CH_CHAIN_TIP, SV2_FFI_ERR_CH_COINBASE, SV2_FFI_ERR_CH_EXTRANONCE_SIZE, SV2_FFI_ERR_CH_JOB_ID,
    SV2_FFI_ERR_CH_MAX_TARGET, SV2_FFI_ERR_CH_NOMINAL_HASHRATE, SV2_FFI_ERR_CH_NTIME_START, SV2_FFI_ERR_CH_OTHER,
    SV2_FFI_ERR_CH_TARGET, SV2_FFI_ERR_SHARE_EXTRANONCE_SIZE,
};
use crate::ffi::{guard, obj, obj_mut, output, ret};
use crate::messages::Sv2FfiSubmitSharesExtended;
use crate::{SV2_FFI_ERR_INTERNAL, SV2_FFI_ERR_OVERFLOW, SV2_FFI_OK};

/// One extended channel.  Opaque to C.
pub struct Sv2FfiExtendedChannel {
    inner: ExtendedChannel,
}

fn err(e: ExtendedChannelError) -> i32 {
    match e {
        ExtendedChannelError::OpenChannelInvalidMaxTarget(_)
        | ExtendedChannelError::UpdateChannelInvalidMaxTarget(_) => SV2_FFI_ERR_CH_MAX_TARGET,
        ExtendedChannelError::OpenChannelInvalidNominalHashrate(_)
        | ExtendedChannelError::UpdateChannelInvalidNominalHashrate(_) => SV2_FFI_ERR_CH_NOMINAL_HASHRATE,
        ExtendedChannelError::RequestedMinExtranonceSizeTooLarge(_) => SV2_FFI_ERR_CH_EXTRANONCE_SIZE,
        ExtendedChannelError::InvalidTarget => SV2_FFI_ERR_CH_TARGET,
        ExtendedChannelError::JobIdNotFound | ExtendedChannelError::TemplateIdNotFound => SV2_FFI_ERR_CH_JOB_ID,
        ExtendedChannelError::ChainTipNotSet => SV2_FFI_ERR_CH_CHAIN_TIP,
        ExtendedChannelError::JobNtimeStartBelowChainTip => SV2_FFI_ERR_CH_NTIME_START,
        ExtendedChannelError::JobFactoryError(JobFactoryError::InvalidPrebuiltCoinbase) => SV2_FFI_ERR_CH_COINBASE,
        _ => SV2_FFI_ERR_CH_OTHER,
    }
}

/// # Safety
/// As `sv2_ffi_extended_channel_new()`.
unsafe fn new(
    allocator: *mut Sv2FfiExtranonceAllocator,
    o: *const Sv2FfiChannelOpen,
) -> Result<Sv2FfiExtendedChannel, i32> {
    // SAFETY: forwarded to the caller
    let (a, o) = unsafe { (obj_mut(allocator)?, obj(o)?) };
    // SAFETY: forwarded to the caller
    let (user, max_target) = unsafe { (user_identity(&o.user_identity)?, le_target(o.max_target)?) };
    let prefix = a
        .inner
        .allocate_extended(o.min_extranonce_size as usize)
        .map_err(alloc_err)?;
    let rollable = a.inner.rollable_extranonce_size() as u16;
    // the prefix goes back to the allocator with the error
    let inner = ExtendedChannel::new_for_pool(
        o.channel_id,
        user,
        prefix,
        max_target,
        o.nominal_hash_rate,
        !o.no_version_rolling,
        rollable,
        o.share_batch_size as usize,
        o.expected_shares_per_minute,
        String::new(),
        (o.max_past_jobs != 0).then_some(o.max_past_jobs as usize),
    )
    .map_err(err)?;
    Ok(Sv2FfiExtendedChannel { inner })
}

/// Open an extended channel with a prefix from `allocator`; the miner rolls
/// the allocator's rollable bytes (`sv2_ffi_extranonce_allocator_rollable_size()`).
/// Version rolling is allowed unless `no_version_rolling` is set.  The
/// channel's target is the crate's, from the nominal hashrate and
/// `expected_shares_per_minute`: read it with
/// `sv2_ffi_extended_channel_target()` for OpenExtendedMiningChannel.Success.
/// Returns NULL with `*status` set when the request is refused, including
/// `SV2_FFI_ERR_INVALID` for a `user_identity` that is not UTF-8, which
/// comes from the miner.  Free with `sv2_ffi_extended_channel_free()`.
///
/// # Safety
/// `allocator` must be a live allocator, `o` must point at a record whose
/// byte fields describe readable memory and whose `max_target` points at 32
/// bytes, and `status` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_new(
    allocator: *mut Sv2FfiExtranonceAllocator,
    o: *const Sv2FfiChannelOpen,
    status: *mut i32,
) -> *mut Sv2FfiExtendedChannel {
    guard(core::ptr::null_mut(), || {
        // SAFETY: forwarded to the caller
        let r = unsafe { new(allocator, o) };
        let (p, s) = match r {
            Ok(ch) => (Box::into_raw(Box::new(ch)), SV2_FFI_OK),
            Err(e) => (core::ptr::null_mut(), e),
        };
        // SAFETY: forwarded to the caller
        if let Ok(status) = unsafe { obj_mut(status) } {
            *status = s;
        }
        p
    })
}

/// Free a channel.  Its extranonce prefix goes back to the allocator, which
/// can hand it to a channel opened later, while the crate keeps the hashes
/// of accepted shares per channel: a new channel with the same prefix, given
/// the same job bytes under the same chain tip, would accept those shares
/// again.  Keep a closed channel until the next SetNewPrevHash before
/// freeing it.  (channels_sv2 10 keeps a dropped prefix reserved under one
/// prev_hash itself: stratum-mining/stratum#2515, not released yet.)
///
/// # Safety
/// `ch` must be NULL or a pointer from `sv2_ffi_extended_channel_new()`,
/// not freed before.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_free(ch: *mut Sv2FfiExtendedChannel) {
    guard((), || {
        if !ch.is_null() {
            // SAFETY: the pointer came from Box::into_raw
            drop(unsafe { Box::from_raw(ch) });
        }
    })
}

/// The channel's extranonce prefix, written to `out` (capacity `cap`).
/// Returns its length, or `SV2_FFI_ERR_OVERFLOW`.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_extranonce_prefix(
    ch: *const Sv2FfiExtendedChannel,
    out: *mut u8,
    cap: u32,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, output(out, cap as usize)?) };
            let prefix = ch.inner.get_extranonce_prefix();
            if prefix.len() > out.len() {
                return Err(SV2_FFI_ERR_OVERFLOW);
            }
            out[..prefix.len()].copy_from_slice(prefix);
            Ok(prefix.len() as i32)
        })())
    })
}

/// The target of the jobs that follow, and of a future job activated after
/// the call: what SetTarget tells the miner.  A job that already takes
/// shares keeps its own.  A zero target, or one above the channel's
/// `max_target` (at open, or from the last UpdateChannel), is refused with
/// `SV2_FFI_ERR_CH_TARGET`.
///
/// # Safety
/// `ch` must be a live channel and `target` must point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_set_target(ch: *mut Sv2FfiExtendedChannel, target: *const u8) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, t) = unsafe { (obj_mut(ch)?, le_target(target)?) };
            ch.inner.set_target(t).map_err(err)?;
            Ok(SV2_FFI_OK)
        })())
    })
}

/// The channel's target, written to `out` (32 bytes, as on the wire): the
/// one the crate derived at open or at the last UpdateChannel, unless a
/// `sv2_ffi_extended_channel_set_target()` came after it.  It is the target
/// of OpenExtendedMiningChannel.Success, and of the SetTarget to send after
/// an UpdateChannel.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_target(ch: *const Sv2FfiExtendedChannel, out: *mut u8) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, output(out, 32)?) };
            out.copy_from_slice(&ch.inner.get_target().to_le_bytes());
            Ok(SV2_FFI_OK)
        })())
    })
}

/// UpdateChannel: the new nominal hashrate and `max_target`.  The crate
/// derives the channel's target from them, at or below `max_target`
/// (`sv2_ffi_extended_channel_target()`), which
/// `sv2_ffi_extended_channel_set_target()` overrides; from now on a target
/// above `max_target` is refused.
///
/// # Safety
/// `ch` must be a live channel and `max_target` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_update(
    ch: *mut Sv2FfiExtendedChannel,
    nominal_hash_rate: f32,
    max_target: *const u8,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, t) = unsafe { (obj_mut(ch)?, le_target(max_target)?) };
            ch.inner.update_channel(nominal_hash_rate, Some(t)).map_err(err)?;
            Ok(SV2_FFI_OK)
        })())
    })
}

/// A job for the channel, as the bytes the server sends it.  A future job
/// (`has_ntime_start` false) waits for `sv2_ffi_extended_channel_activate_job()`;
/// otherwise the job is active under the channel's chain tip and the
/// previous one retires to the past jobs, still accepting shares.  An
/// active job needs the chain tip (`SV2_FFI_ERR_CH_CHAIN_TIP`) and an
/// `ntime_start` no lower than the tip's (`SV2_FFI_ERR_CH_NTIME_START`).
/// `*job_id` is the id the miner is told.  The NewExtendedMiningJob sent
/// for it carries `version_rolling_allowed` false on a channel opened with
/// `no_version_rolling`: the channel refuses rolled versions there.
///
/// # Safety
/// `ch` must be a live channel, `job` must point at a record whose byte
/// fields describe readable memory, and `job_id` must be writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_prebuilt_job(
    ch: *mut Sv2FfiExtendedChannel,
    job: *const Sv2FfiPrebuiltJob,
    job_id: *mut u32,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, job, job_id) = unsafe { (obj_mut(ch)?, prebuilt(job)?, obj_mut(job_id)?) };
            *job_id = ch.inner.on_prebuilt_job(job).map_err(err)?;
            Ok(SV2_FFI_OK)
        })())
    })
}

/// The target shares on job `job_id` are checked against, and the one an
/// accepted share is credited at: the channel's target when the job was
/// created or activated, written to `out` (32 bytes, as on the wire).
/// Returns `SV2_FFI_ERR_CH_JOB_ID` for a job the channel takes no shares
/// on: unknown, future, evicted from the past jobs, or stale.
///
/// # Safety
/// `ch` must be a live channel and `out` must point at 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_job_target(
    ch: *const Sv2FfiExtendedChannel,
    job_id: u32,
    out: *mut u8,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, output(out, 32)?) };
            let t = ch.inner.get_job_target(job_id).ok_or(SV2_FFI_ERR_CH_JOB_ID)?;
            out.copy_from_slice(&t.to_le_bytes());
            Ok(SV2_FFI_OK)
        })())
    })
}

/// SetNewPrevHash: the future job `job_id` is the active job under the tip
/// `prev_hash` (32 bytes as on the wire), `nbits`, `ntime_start`.  The
/// active and past jobs go stale, and the other future jobs are dropped: a
/// share on one of those is `SV2_FFI_ERR_SHARE_JOB_ID`, not
/// `SV2_FFI_ERR_SHARE_STALE`.
///
/// # Safety
/// `ch` must be a live channel and `prev_hash` must point at 32 readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_activate_job(
    ch: *mut Sv2FfiExtendedChannel,
    job_id: u32,
    prev_hash: *const u8,
    nbits: u32,
    ntime_start: u32,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, tip) = unsafe { (obj_mut(ch)?, chain_tip(prev_hash, nbits, ntime_start)?) };
            ch.inner.activate_future_job(job_id, tip).map_err(err)?;
            Ok(SV2_FFI_OK)
        })())
    })
}

/// Validate a SubmitSharesExtended.  Returns `SV2_FFI_SHARE_VALID` or
/// `SV2_FFI_SHARE_BLOCK` with the share hash in `hash` (32 bytes), or a
/// `SV2_FFI_ERR_SHARE_*` code.  A NULL `hash` is `SV2_FFI_ERR_INVALID`
/// before the share is looked at.  The crate counts accepted shares, and
/// refused ones that have a SubmitShares.Error code, in the channel's share
/// accounting; an extranonce over 32 bytes, which no decoded message
/// carries, is `SV2_FFI_ERR_SHARE_EXTRANONCE_SIZE` before the crate sees
/// the share, and is not counted.
///
/// With a block, `*coinbase_len` gets the length of the block's coinbase
/// (the job's prefix, the extranonce and the job's suffix as handed over,
/// no witness data), and the bytes go to `coinbase` only when that length
/// is at most `coinbase_cap`; otherwise `*coinbase_len` is above
/// `coinbase_cap` and `coinbase` is untouched.  The same share sent again is
/// a duplicate, so size `coinbase` before: the job's prefix and suffix
/// lengths plus 32 always fit.  For anything but a block `*coinbase_len` is
/// 0.  Pass NULL, 0, NULL to skip the coinbase.
///
/// # Safety
/// `ch` must be a live channel, `share` must point at a record whose
/// `extranonce` describes readable memory, `hash` must point at 32
/// writable bytes, `coinbase` must be NULL or point at `coinbase_cap`
/// writable bytes, and `coinbase_len` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_validate_share(
    ch: *mut Sv2FfiExtendedChannel,
    share: *const Sv2FfiSubmitSharesExtended,
    hash: *mut u8,
    coinbase: *mut u8,
    coinbase_cap: u32,
    coinbase_len: *mut u32,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // `*coinbase_len` first, so that every return sets it
            // SAFETY: forwarded to the caller
            if let Some(len) = unsafe { coinbase_len.as_mut() } {
                *len = 0;
            }
            // SAFETY: forwarded to the caller
            let (ch, s, hash) = unsafe { (obj_mut(ch)?, obj(share)?, hash_out(hash)?) };
            // SAFETY: forwarded to the caller
            let extranonce = unsafe { s.extranonce.as_slice()? };
            let share = SubmitSharesExtendedOwned {
                channel_id: ch.inner.get_channel_id(),
                sequence_number: s.sequence_number,
                job_id: s.job_id,
                nonce: s.nonce,
                ntime: s.ntime,
                version: s.version,
                // B032 holds what the channel's own size check would refuse
                extranonce: B032Owned::new(extranonce.to_vec()).map_err(|_| SV2_FFI_ERR_SHARE_EXTRANONCE_SIZE)?,
            };
            // SAFETY: forwarded to the caller
            Ok(unsafe {
                share_status(
                    ch.inner.validate_share(share),
                    hash,
                    coinbase,
                    coinbase_cap,
                    coinbase_len,
                )
            })
        })())
    })
}

/// The channel's share accounting, as the crate updates it on every share
/// it validates, written to `*out`.  After `SV2_FFI_SHARE_VALID`, a true
/// `should_acknowledge` means the batch is full: send SubmitShares.Success
/// with `last_share_sequence_number`, `last_batch_accepted` and
/// `last_batch_work_sum`.  After `SV2_FFI_SHARE_BLOCK` send it whatever
/// `should_acknowledge` says: the crate starts the next batch with the next
/// accepted share.
///
/// # Safety
/// `ch` must be a live channel and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn sv2_ffi_extended_channel_share_accounting(
    ch: *const Sv2FfiExtendedChannel,
    out: *mut Sv2FfiShareAccounting,
) -> i32 {
    guard(SV2_FFI_ERR_INTERNAL, || {
        ret((|| {
            // SAFETY: forwarded to the caller
            let (ch, out) = unsafe { (obj(ch)?, obj_mut(out)?) };
            *out = accounting(ch.inner.get_share_accounting());
            Ok(SV2_FFI_OK)
        })())
    })
}
