// The common and mining messages as C records, dispatched by parsers_sv2.
//
// The Noise session (codec.rs) hands every frame it decrypts to `decode()`,
// which turns it into a `Sv2FfiMessage`: parsers_sv2 decides from the frame
// header which message it is and whether it belongs to an extension.
// `frame()` is the other direction, with the message type and the
// channel_msg bit coming from the subprotocol crates.  What is here is the
// records and the field-by-field conversions between them and the crates'
// structs, which is what a binding is for.

use core::slice;

use binary_sv2::{Seq0255, Seq064K, Str0255, Sv2Option, B0255, B032, B064K, U256};
use codec_sv2::EncodableFrame;
use common_messages_sv2::{
    ChannelEndpointChanged, Protocol, Reconnect, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
};
use framing_sv2::{framing::MessageFrame, header::Header};
use mining_sv2::{
    CloseChannel, NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess,
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess, SetCustomMiningJob,
    SetCustomMiningJobError, SetCustomMiningJobSuccess, SetExtranoncePrefix, SetGroupChannel, SetNewPrevHash,
    SetTarget, SubmitSharesError, SubmitSharesExtended, SubmitSharesStandard, SubmitSharesSuccess, UpdateChannel,
    UpdateChannelError,
};
use parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message, Mining, ParserError};

use crate::ffi::{binary_err, Sv2FfiBytes};
use crate::{SV2_FFI_ERR_INVALID, SV2_FFI_ERR_UNSUPPORTED};

/////////////////////////////////
// Message types
/////////////////////////////////

// The values the subprotocol crates assign; `Sv2FfiMessage::msg_type` holds
// one of these.  cbindgen only sees literals, so they are checked against
// the crates below.

/// SetupConnection
pub const SV2_FFI_MSG_SETUP_CONNECTION: u8 = 0x00;
/// SetupConnection.Success
pub const SV2_FFI_MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
/// SetupConnection.Error
pub const SV2_FFI_MSG_SETUP_CONNECTION_ERROR: u8 = 0x02;
/// ChannelEndpointChanged
pub const SV2_FFI_MSG_CHANNEL_ENDPOINT_CHANGED: u8 = 0x03;
/// Reconnect
pub const SV2_FFI_MSG_RECONNECT: u8 = 0x04;
/// OpenStandardMiningChannel
pub const SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
/// OpenStandardMiningChannel.Success
pub const SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
/// OpenMiningChannel.Error
pub const SV2_FFI_MSG_OPEN_MINING_CHANNEL_ERROR: u8 = 0x12;
/// OpenExtendedMiningChannel
pub const SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL: u8 = 0x13;
/// OpenExtendedMiningChannel.Success
pub const SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: u8 = 0x14;
/// NewMiningJob
pub const SV2_FFI_MSG_NEW_MINING_JOB: u8 = 0x15;
/// UpdateChannel
pub const SV2_FFI_MSG_UPDATE_CHANNEL: u8 = 0x16;
/// UpdateChannel.Error
pub const SV2_FFI_MSG_UPDATE_CHANNEL_ERROR: u8 = 0x17;
/// CloseChannel
pub const SV2_FFI_MSG_CLOSE_CHANNEL: u8 = 0x18;
/// SetExtranoncePrefix
pub const SV2_FFI_MSG_SET_EXTRANONCE_PREFIX: u8 = 0x19;
/// SubmitSharesStandard
pub const SV2_FFI_MSG_SUBMIT_SHARES_STANDARD: u8 = 0x1a;
/// SubmitSharesExtended
pub const SV2_FFI_MSG_SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
/// SubmitShares.Success
pub const SV2_FFI_MSG_SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
/// SubmitShares.Error
pub const SV2_FFI_MSG_SUBMIT_SHARES_ERROR: u8 = 0x1d;
/// NewExtendedMiningJob
pub const SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB: u8 = 0x1f;
/// SetNewPrevHash of the mining protocol
pub const SV2_FFI_MSG_SET_NEW_PREV_HASH_MINING: u8 = 0x20;
/// SetTarget
pub const SV2_FFI_MSG_SET_TARGET: u8 = 0x21;
/// SetCustomMiningJob
pub const SV2_FFI_MSG_SET_CUSTOM_MINING_JOB: u8 = 0x22;
/// SetCustomMiningJob.Success
pub const SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS: u8 = 0x23;
/// SetCustomMiningJob.Error
pub const SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR: u8 = 0x24;
/// SetGroupChannel
pub const SV2_FFI_MSG_SET_GROUP_CHANNEL: u8 = 0x25;

const _: () = {
    use common_messages_sv2 as c;
    use mining_sv2 as m;
    assert!(SV2_FFI_MSG_SETUP_CONNECTION == c::MESSAGE_TYPE_SETUP_CONNECTION);
    assert!(SV2_FFI_MSG_SETUP_CONNECTION_SUCCESS == c::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
    assert!(SV2_FFI_MSG_SETUP_CONNECTION_ERROR == c::MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    assert!(SV2_FFI_MSG_CHANNEL_ENDPOINT_CHANGED == c::MESSAGE_TYPE_CHANNEL_ENDPOINT_CHANGED);
    assert!(SV2_FFI_MSG_RECONNECT == c::MESSAGE_TYPE_RECONNECT);
    assert!(SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL == m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL);
    assert!(SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS == m::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS);
    assert!(SV2_FFI_MSG_OPEN_MINING_CHANNEL_ERROR == m::MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR);
    assert!(SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL == m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL);
    assert!(SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS == m::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS);
    assert!(SV2_FFI_MSG_NEW_MINING_JOB == m::MESSAGE_TYPE_NEW_MINING_JOB);
    assert!(SV2_FFI_MSG_UPDATE_CHANNEL == m::MESSAGE_TYPE_UPDATE_CHANNEL);
    assert!(SV2_FFI_MSG_UPDATE_CHANNEL_ERROR == m::MESSAGE_TYPE_UPDATE_CHANNEL_ERROR);
    assert!(SV2_FFI_MSG_CLOSE_CHANNEL == m::MESSAGE_TYPE_CLOSE_CHANNEL);
    assert!(SV2_FFI_MSG_SET_EXTRANONCE_PREFIX == m::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX);
    assert!(SV2_FFI_MSG_SUBMIT_SHARES_STANDARD == m::MESSAGE_TYPE_SUBMIT_SHARES_STANDARD);
    assert!(SV2_FFI_MSG_SUBMIT_SHARES_EXTENDED == m::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED);
    assert!(SV2_FFI_MSG_SUBMIT_SHARES_SUCCESS == m::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
    assert!(SV2_FFI_MSG_SUBMIT_SHARES_ERROR == m::MESSAGE_TYPE_SUBMIT_SHARES_ERROR);
    assert!(SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB == m::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB);
    assert!(SV2_FFI_MSG_SET_NEW_PREV_HASH_MINING == m::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH);
    assert!(SV2_FFI_MSG_SET_TARGET == m::MESSAGE_TYPE_SET_TARGET);
    assert!(SV2_FFI_MSG_SET_CUSTOM_MINING_JOB == m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB);
    assert!(SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS == m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS);
    assert!(SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR == m::MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR);
    assert!(SV2_FFI_MSG_SET_GROUP_CHANNEL == m::MESSAGE_TYPE_SET_GROUP_CHANNEL);
};

/////////////////////////////////
// Records
/////////////////////////////////

/// SetupConnection (0x00)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetupConnection {
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: Sv2FfiBytes,
    pub endpoint_port: u16,
    pub vendor: Sv2FfiBytes,
    pub hardware_version: Sv2FfiBytes,
    pub firmware: Sv2FfiBytes,
    pub device_id: Sv2FfiBytes,
}

/// SetupConnection.Success (0x01)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetupConnectionSuccess {
    pub used_version: u16,
    pub flags: u32,
}

/// SetupConnection.Error (0x02)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetupConnectionError {
    pub flags: u32,
    pub error_code: Sv2FfiBytes,
}

/// ChannelEndpointChanged (0x03)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiChannelEndpointChanged {
    pub channel_id: u32,
}

/// Reconnect (0x04)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiReconnect {
    pub new_host: Sv2FfiBytes,
    pub new_port: u16,
}

/// OpenStandardMiningChannel (0x10)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiOpenStandardMiningChannel {
    pub request_id: u32,
    pub user_identity: Sv2FfiBytes,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
}

/// OpenStandardMiningChannel.Success (0x11)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiOpenStandardMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    pub target: [u8; 32],
    pub extranonce_prefix: Sv2FfiBytes,
    pub group_channel_id: u32,
}

/// OpenMiningChannel.Error (0x12)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiOpenMiningChannelError {
    pub request_id: u32,
    pub error_code: Sv2FfiBytes,
}

/// OpenExtendedMiningChannel (0x13)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiOpenExtendedMiningChannel {
    pub request_id: u32,
    pub user_identity: Sv2FfiBytes,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
    pub min_extranonce_size: u16,
}

/// OpenExtendedMiningChannel.Success (0x14)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiOpenExtendedMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    pub target: [u8; 32],
    pub extranonce_size: u16,
    pub extranonce_prefix: Sv2FfiBytes,
    pub group_channel_id: u32,
}

/// UpdateChannel (0x16)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiUpdateChannel {
    pub channel_id: u32,
    pub nominal_hash_rate: f32,
    pub max_target: [u8; 32],
}

/// UpdateChannel.Error (0x17)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiUpdateChannelError {
    pub channel_id: u32,
    pub error_code: Sv2FfiBytes,
}

/// CloseChannel (0x18)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiCloseChannel {
    pub channel_id: u32,
    pub reason_code: Sv2FfiBytes,
}

/// SetExtranoncePrefix (0x19)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetExtranoncePrefix {
    pub channel_id: u32,
    pub extranonce_prefix: Sv2FfiBytes,
}

/// SetTarget (0x21)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetTarget {
    pub channel_id: u32,
    pub target: [u8; 32],
}

/// SetGroupChannel (0x25).  `channel_ids` is `channel_ids_count` little
/// endian u32 values.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetGroupChannel {
    pub group_channel_id: u32,
    pub channel_ids_count: u16,
    pub channel_ids: Sv2FfiBytes,
}

/// NewMiningJob (0x15).  `has_ntime_start` false is a future job.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiNewMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub has_ntime_start: bool,
    pub ntime_start: u32,
    pub version: u32,
    pub merkle_root: [u8; 32],
}

/// NewExtendedMiningJob (0x1f).  `merkle_path` is `merkle_path_count`
/// 32 byte hashes back to back.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiNewExtendedMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub has_ntime_start: bool,
    pub ntime_start: u32,
    pub version: u32,
    pub version_rolling_allowed: bool,
    pub merkle_path_count: u8,
    pub merkle_path: Sv2FfiBytes,
    pub coinbase_tx_prefix: Sv2FfiBytes,
    pub coinbase_tx_suffix: Sv2FfiBytes,
}

/// SetNewPrevHash of the mining protocol (0x20)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetNewPrevHashMining {
    pub channel_id: u32,
    pub job_id: u32,
    pub prev_hash: [u8; 32],
    pub ntime_start: u32,
    pub nbits: u32,
}

/// SetCustomMiningJob (0x22).  `merkle_path` is `merkle_path_count` 32
/// byte hashes back to back.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetCustomMiningJob {
    pub channel_id: u32,
    pub request_id: u32,
    pub token: Sv2FfiBytes,
    pub version: u32,
    pub prev_hash: [u8; 32],
    pub ntime_start: u32,
    pub nbits: u32,
    pub coinbase_tx_version: u32,
    pub coinbase_prefix: Sv2FfiBytes,
    pub coinbase_tx_input_n_sequence: u32,
    pub coinbase_tx_outputs: Sv2FfiBytes,
    pub coinbase_tx_locktime: u32,
    pub merkle_path_count: u8,
    pub merkle_path: Sv2FfiBytes,
}

/// SetCustomMiningJob.Success (0x23)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetCustomMiningJobSuccess {
    pub channel_id: u32,
    pub request_id: u32,
    pub job_id: u32,
}

/// SetCustomMiningJob.Error (0x24)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSetCustomMiningJobError {
    pub channel_id: u32,
    pub request_id: u32,
    pub error_code: Sv2FfiBytes,
}

/// SubmitSharesStandard (0x1a)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSubmitSharesStandard {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

/// SubmitSharesExtended (0x1b)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSubmitSharesExtended {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
    pub extranonce: Sv2FfiBytes,
}

/// SubmitShares.Success (0x1c)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSubmitSharesSuccess {
    pub channel_id: u32,
    pub last_sequence_number: u32,
    pub new_submits_accepted_count: u32,
    pub new_shares_sum: u64,
}

/// SubmitShares.Error (0x1d)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiSubmitSharesError {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub error_code: Sv2FfiBytes,
}

/// The record of one message; `Sv2FfiMessage::msg_type` says which member
/// is live.
#[repr(C)]
#[derive(Clone, Copy)]
pub union Sv2FfiMessageUnion {
    pub setup_connection: Sv2FfiSetupConnection,
    pub setup_connection_success: Sv2FfiSetupConnectionSuccess,
    pub setup_connection_error: Sv2FfiSetupConnectionError,
    pub channel_endpoint_changed: Sv2FfiChannelEndpointChanged,
    pub reconnect: Sv2FfiReconnect,
    pub open_standard_mining_channel: Sv2FfiOpenStandardMiningChannel,
    pub open_standard_mining_channel_success: Sv2FfiOpenStandardMiningChannelSuccess,
    pub open_mining_channel_error: Sv2FfiOpenMiningChannelError,
    pub open_extended_mining_channel: Sv2FfiOpenExtendedMiningChannel,
    pub open_extended_mining_channel_success: Sv2FfiOpenExtendedMiningChannelSuccess,
    pub update_channel: Sv2FfiUpdateChannel,
    pub update_channel_error: Sv2FfiUpdateChannelError,
    pub close_channel: Sv2FfiCloseChannel,
    pub set_extranonce_prefix: Sv2FfiSetExtranoncePrefix,
    pub set_target: Sv2FfiSetTarget,
    pub set_group_channel: Sv2FfiSetGroupChannel,
    pub new_mining_job: Sv2FfiNewMiningJob,
    pub new_extended_mining_job: Sv2FfiNewExtendedMiningJob,
    pub set_new_prev_hash_mining: Sv2FfiSetNewPrevHashMining,
    pub set_custom_mining_job: Sv2FfiSetCustomMiningJob,
    pub set_custom_mining_job_success: Sv2FfiSetCustomMiningJobSuccess,
    pub set_custom_mining_job_error: Sv2FfiSetCustomMiningJobError,
    pub submit_shares_standard: Sv2FfiSubmitSharesStandard,
    pub submit_shares_extended: Sv2FfiSubmitSharesExtended,
    pub submit_shares_success: Sv2FfiSubmitSharesSuccess,
    pub submit_shares_error: Sv2FfiSubmitSharesError,
}

/// One decoded message, or one to encode: the message type (one of the
/// `SV2_FFI_MSG_*` values) and its record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sv2FfiMessage {
    pub msg_type: u8,
    pub u: Sv2FfiMessageUnion,
}

/////////////////////////////////
// Conversions
/////////////////////////////////

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn str0255<'a>(b: &Sv2FfiBytes) -> Result<Str0255<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    Str0255::try_from(s).map_err(|_| SV2_FFI_ERR_INVALID)
}

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn b032<'a>(b: &Sv2FfiBytes) -> Result<B032<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    B032::try_from(s).map_err(|_| SV2_FFI_ERR_INVALID)
}

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn b064k<'a>(b: &Sv2FfiBytes) -> Result<B064K<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    B064K::try_from(s).map_err(|_| SV2_FFI_ERR_INVALID)
}

/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn b0255<'a>(b: &Sv2FfiBytes) -> Result<B0255<'a>, i32> {
    // SAFETY: forwarded to the caller
    let s: &'a [u8] = unsafe { b.as_slice()? };
    B0255::try_from(s).map_err(|_| SV2_FFI_ERR_INVALID)
}

fn u256(a: &[u8; 32]) -> Result<U256<'_>, i32> {
    U256::try_from(&a[..]).map_err(|_| SV2_FFI_ERR_INVALID)
}

/// A merkle path record: `count` hashes of 32 bytes back to back.
///
/// # Safety
/// `b` must describe readable memory that outlives `'a`.
unsafe fn merkle_path<'a>(count: u8, b: &Sv2FfiBytes) -> Result<Seq0255<'a, U256<'a>>, i32> {
    // SAFETY: forwarded to the caller
    let path: &'a [u8] = unsafe { b.as_slice()? };
    if path.len() != count as usize * 32 {
        return Err(SV2_FFI_ERR_INVALID);
    }
    let mut hashes = Vec::with_capacity(count as usize);
    for h in path.chunks_exact(32) {
        hashes.push(U256::try_from(h).map_err(|_| SV2_FFI_ERR_INVALID)?);
    }
    Seq0255::new(hashes).map_err(|_| SV2_FFI_ERR_INVALID)
}

/// What an empty decoded merkle path points at: like every other byte field
/// of a decoded record, its `data` is not NULL, so a C caller can hand it
/// to memcpy with its length of 0.
static NO_HASHES: [u8; 1] = [0];

/// The record of a decoded merkle path.  The hashes sit back to back in the
/// payload after their u8 count; binary_sv2 hands them out one by one, so
/// check they are contiguous before describing them as one range.
fn merkle_path_view(path: &[U256<'_>]) -> Result<(u8, Sv2FfiBytes), i32> {
    let Some(first) = path.first() else {
        return Ok((0, Sv2FfiBytes::from_slice(&NO_HASHES[..0])));
    };
    let base = first.as_bytes().as_ptr();
    for (i, h) in path.iter().enumerate() {
        if h.as_bytes().as_ptr() != base.wrapping_add(i * 32) {
            return Err(SV2_FFI_ERR_INVALID);
        }
    }
    let view = Sv2FfiBytes {
        data: base,
        len: (path.len() * 32) as u32,
    };
    Ok((path.len() as u8, view))
}

fn view(b: &[u8]) -> Sv2FfiBytes {
    Sv2FfiBytes::from_slice(b)
}

fn arr32(src: &U256<'_>) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(src.as_bytes());
    a
}

fn opt_ntime(has: bool, v: u32) -> Sv2Option<'static, u32> {
    Sv2Option::new(if has { Some(v) } else { None })
}

/// The crates' message for a record.  The byte fields of `m` are borrowed
/// for as long as the message lives.
///
/// # Safety
/// Every byte field of the live record must describe readable memory that
/// outlives the returned message.
unsafe fn to_any(m: &Sv2FfiMessage) -> Result<AnyMessage<'_>, i32> {
    use Mining as M;
    // SAFETY: the member read matches the tag, and the byte fields are the
    // caller's
    unsafe {
        Ok(match m.msg_type {
            SV2_FFI_MSG_SETUP_CONNECTION => {
                let c = &m.u.setup_connection;
                CommonMessages::SetupConnection(SetupConnection {
                    protocol: Protocol::try_from(c.protocol).map_err(|_| SV2_FFI_ERR_INVALID)?,
                    min_version: c.min_version,
                    max_version: c.max_version,
                    flags: c.flags,
                    endpoint_host: str0255(&c.endpoint_host)?,
                    endpoint_port: c.endpoint_port,
                    vendor: str0255(&c.vendor)?,
                    hardware_version: str0255(&c.hardware_version)?,
                    firmware: str0255(&c.firmware)?,
                    device_id: str0255(&c.device_id)?,
                })
                .into()
            }
            SV2_FFI_MSG_SETUP_CONNECTION_SUCCESS => {
                let c = &m.u.setup_connection_success;
                CommonMessages::SetupConnectionSuccess(SetupConnectionSuccess {
                    used_version: c.used_version,
                    flags: c.flags,
                })
                .into()
            }
            SV2_FFI_MSG_SETUP_CONNECTION_ERROR => {
                let c = &m.u.setup_connection_error;
                CommonMessages::SetupConnectionError(SetupConnectionError {
                    flags: c.flags,
                    error_code: str0255(&c.error_code)?,
                })
                .into()
            }
            SV2_FFI_MSG_CHANNEL_ENDPOINT_CHANGED => {
                let c = &m.u.channel_endpoint_changed;
                CommonMessages::ChannelEndpointChanged(ChannelEndpointChanged {
                    channel_id: c.channel_id,
                })
                .into()
            }
            SV2_FFI_MSG_RECONNECT => {
                let c = &m.u.reconnect;
                CommonMessages::Reconnect(Reconnect {
                    new_host: str0255(&c.new_host)?,
                    new_port: c.new_port,
                })
                .into()
            }
            SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL => {
                let c = &m.u.open_standard_mining_channel;
                AnyMessage::Mining(M::OpenStandardMiningChannel(OpenStandardMiningChannel {
                    request_id: c.request_id,
                    user_identity: str0255(&c.user_identity)?,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.max_target)?,
                }))
            }
            SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
                let c = &m.u.open_standard_mining_channel_success;
                AnyMessage::Mining(M::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
                    request_id: c.request_id,
                    channel_id: c.channel_id,
                    target: u256(&c.target)?,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                    group_channel_id: c.group_channel_id,
                }))
            }
            SV2_FFI_MSG_OPEN_MINING_CHANNEL_ERROR => {
                let c = &m.u.open_mining_channel_error;
                AnyMessage::Mining(M::OpenMiningChannelError(OpenMiningChannelError {
                    request_id: c.request_id,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL => {
                let c = &m.u.open_extended_mining_channel;
                AnyMessage::Mining(M::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
                    request_id: c.request_id,
                    user_identity: str0255(&c.user_identity)?,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.max_target)?,
                    min_extranonce_size: c.min_extranonce_size,
                }))
            }
            SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => {
                let c = &m.u.open_extended_mining_channel_success;
                AnyMessage::Mining(M::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
                    request_id: c.request_id,
                    channel_id: c.channel_id,
                    target: u256(&c.target)?,
                    extranonce_size: c.extranonce_size,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                    group_channel_id: c.group_channel_id,
                }))
            }
            SV2_FFI_MSG_UPDATE_CHANNEL => {
                let c = &m.u.update_channel;
                AnyMessage::Mining(M::UpdateChannel(UpdateChannel {
                    channel_id: c.channel_id,
                    nominal_hash_rate: c.nominal_hash_rate,
                    max_target: u256(&c.max_target)?,
                }))
            }
            SV2_FFI_MSG_UPDATE_CHANNEL_ERROR => {
                let c = &m.u.update_channel_error;
                AnyMessage::Mining(M::UpdateChannelError(UpdateChannelError {
                    channel_id: c.channel_id,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            SV2_FFI_MSG_CLOSE_CHANNEL => {
                let c = &m.u.close_channel;
                AnyMessage::Mining(M::CloseChannel(CloseChannel {
                    channel_id: c.channel_id,
                    reason_code: str0255(&c.reason_code)?,
                }))
            }
            SV2_FFI_MSG_SET_EXTRANONCE_PREFIX => {
                let c = &m.u.set_extranonce_prefix;
                AnyMessage::Mining(M::SetExtranoncePrefix(SetExtranoncePrefix {
                    channel_id: c.channel_id,
                    extranonce_prefix: b032(&c.extranonce_prefix)?,
                }))
            }
            SV2_FFI_MSG_SET_TARGET => {
                let c = &m.u.set_target;
                AnyMessage::Mining(M::SetTarget(SetTarget {
                    channel_id: c.channel_id,
                    target: u256(&c.target)?,
                }))
            }
            SV2_FFI_MSG_SET_GROUP_CHANNEL => {
                let c = &m.u.set_group_channel;
                let raw = c.channel_ids.as_slice()?;
                if raw.len() != c.channel_ids_count as usize * 4 {
                    return Err(SV2_FFI_ERR_INVALID);
                }
                let ids = raw
                    .chunks_exact(4)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .collect();
                AnyMessage::Mining(M::SetGroupChannel(SetGroupChannel {
                    group_channel_id: c.group_channel_id,
                    channel_ids: Seq064K::new(ids).map_err(|_| SV2_FFI_ERR_INVALID)?,
                }))
            }
            SV2_FFI_MSG_NEW_MINING_JOB => {
                let c = &m.u.new_mining_job;
                AnyMessage::Mining(M::NewMiningJob(NewMiningJob {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    ntime_start: opt_ntime(c.has_ntime_start, c.ntime_start),
                    version: c.version,
                    merkle_root: u256(&c.merkle_root)?,
                }))
            }
            SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB => {
                let c = &m.u.new_extended_mining_job;
                AnyMessage::Mining(M::NewExtendedMiningJob(NewExtendedMiningJob {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    ntime_start: opt_ntime(c.has_ntime_start, c.ntime_start),
                    version: c.version,
                    version_rolling_allowed: c.version_rolling_allowed,
                    merkle_path: merkle_path(c.merkle_path_count, &c.merkle_path)?,
                    coinbase_tx_prefix: b064k(&c.coinbase_tx_prefix)?,
                    coinbase_tx_suffix: b064k(&c.coinbase_tx_suffix)?,
                }))
            }
            SV2_FFI_MSG_SET_NEW_PREV_HASH_MINING => {
                let c = &m.u.set_new_prev_hash_mining;
                AnyMessage::Mining(M::SetNewPrevHash(SetNewPrevHash {
                    channel_id: c.channel_id,
                    job_id: c.job_id,
                    prev_hash: u256(&c.prev_hash)?,
                    ntime_start: c.ntime_start,
                    nbits: c.nbits,
                }))
            }
            SV2_FFI_MSG_SET_CUSTOM_MINING_JOB => {
                let c = &m.u.set_custom_mining_job;
                AnyMessage::Mining(M::SetCustomMiningJob(SetCustomMiningJob {
                    channel_id: c.channel_id,
                    request_id: c.request_id,
                    token: b0255(&c.token)?,
                    version: c.version,
                    prev_hash: u256(&c.prev_hash)?,
                    ntime_start: c.ntime_start,
                    nbits: c.nbits,
                    coinbase_tx_version: c.coinbase_tx_version,
                    coinbase_prefix: b0255(&c.coinbase_prefix)?,
                    coinbase_tx_input_n_sequence: c.coinbase_tx_input_n_sequence,
                    coinbase_tx_outputs: b064k(&c.coinbase_tx_outputs)?,
                    coinbase_tx_locktime: c.coinbase_tx_locktime,
                    merkle_path: merkle_path(c.merkle_path_count, &c.merkle_path)?,
                }))
            }
            SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS => {
                let c = &m.u.set_custom_mining_job_success;
                AnyMessage::Mining(M::SetCustomMiningJobSuccess(SetCustomMiningJobSuccess {
                    channel_id: c.channel_id,
                    request_id: c.request_id,
                    job_id: c.job_id,
                }))
            }
            SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR => {
                let c = &m.u.set_custom_mining_job_error;
                AnyMessage::Mining(M::SetCustomMiningJobError(SetCustomMiningJobError {
                    channel_id: c.channel_id,
                    request_id: c.request_id,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            SV2_FFI_MSG_SUBMIT_SHARES_STANDARD => {
                let c = &m.u.submit_shares_standard;
                AnyMessage::Mining(M::SubmitSharesStandard(SubmitSharesStandard {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    job_id: c.job_id,
                    nonce: c.nonce,
                    ntime: c.ntime,
                    version: c.version,
                }))
            }
            SV2_FFI_MSG_SUBMIT_SHARES_EXTENDED => {
                let c = &m.u.submit_shares_extended;
                AnyMessage::Mining(M::SubmitSharesExtended(SubmitSharesExtended {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    job_id: c.job_id,
                    nonce: c.nonce,
                    ntime: c.ntime,
                    version: c.version,
                    extranonce: b032(&c.extranonce)?,
                }))
            }
            SV2_FFI_MSG_SUBMIT_SHARES_SUCCESS => {
                let c = &m.u.submit_shares_success;
                AnyMessage::Mining(M::SubmitSharesSuccess(SubmitSharesSuccess {
                    channel_id: c.channel_id,
                    last_sequence_number: c.last_sequence_number,
                    new_submits_accepted_count: c.new_submits_accepted_count,
                    new_shares_sum: c.new_shares_sum,
                }))
            }
            SV2_FFI_MSG_SUBMIT_SHARES_ERROR => {
                let c = &m.u.submit_shares_error;
                AnyMessage::Mining(M::SubmitSharesError(SubmitSharesError {
                    channel_id: c.channel_id,
                    sequence_number: c.sequence_number,
                    error_code: str0255(&c.error_code)?,
                }))
            }
            _ => return Err(SV2_FFI_ERR_INVALID),
        })
    }
}

/// The record for a decoded message.  Byte fields point into the payload
/// the message was decoded from.
fn to_record(msg: &AnyMessage<'_>) -> Result<Sv2FfiMessage, i32> {
    use Mining as M;
    let msg_type = msg.message_type();
    let u = match msg {
        AnyMessage::Common(CommonMessages::SetupConnection(m)) => Sv2FfiMessageUnion {
            setup_connection: Sv2FfiSetupConnection {
                protocol: m.protocol as u8,
                min_version: m.min_version,
                max_version: m.max_version,
                flags: m.flags,
                endpoint_host: view(m.endpoint_host.as_bytes()),
                endpoint_port: m.endpoint_port,
                vendor: view(m.vendor.as_bytes()),
                hardware_version: view(m.hardware_version.as_bytes()),
                firmware: view(m.firmware.as_bytes()),
                device_id: view(m.device_id.as_bytes()),
            },
        },
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(m)) => Sv2FfiMessageUnion {
            setup_connection_success: Sv2FfiSetupConnectionSuccess {
                used_version: m.used_version,
                flags: m.flags,
            },
        },
        AnyMessage::Common(CommonMessages::SetupConnectionError(m)) => Sv2FfiMessageUnion {
            setup_connection_error: Sv2FfiSetupConnectionError {
                flags: m.flags,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Common(CommonMessages::ChannelEndpointChanged(m)) => Sv2FfiMessageUnion {
            channel_endpoint_changed: Sv2FfiChannelEndpointChanged {
                channel_id: m.channel_id,
            },
        },
        AnyMessage::Common(CommonMessages::Reconnect(m)) => Sv2FfiMessageUnion {
            reconnect: Sv2FfiReconnect {
                new_host: view(m.new_host.as_bytes()),
                new_port: m.new_port,
            },
        },
        AnyMessage::Mining(M::OpenStandardMiningChannel(m)) => Sv2FfiMessageUnion {
            open_standard_mining_channel: Sv2FfiOpenStandardMiningChannel {
                request_id: m.request_id,
                user_identity: view(m.user_identity.as_bytes()),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: arr32(&m.max_target),
            },
        },
        AnyMessage::Mining(M::OpenStandardMiningChannelSuccess(m)) => Sv2FfiMessageUnion {
            open_standard_mining_channel_success: Sv2FfiOpenStandardMiningChannelSuccess {
                request_id: m.request_id,
                channel_id: m.channel_id,
                target: arr32(&m.target),
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
                group_channel_id: m.group_channel_id,
            },
        },
        AnyMessage::Mining(M::OpenMiningChannelError(m)) => Sv2FfiMessageUnion {
            open_mining_channel_error: Sv2FfiOpenMiningChannelError {
                request_id: m.request_id,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::OpenExtendedMiningChannel(m)) => Sv2FfiMessageUnion {
            open_extended_mining_channel: Sv2FfiOpenExtendedMiningChannel {
                request_id: m.request_id,
                user_identity: view(m.user_identity.as_bytes()),
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: arr32(&m.max_target),
                min_extranonce_size: m.min_extranonce_size,
            },
        },
        AnyMessage::Mining(M::OpenExtendedMiningChannelSuccess(m)) => Sv2FfiMessageUnion {
            open_extended_mining_channel_success: Sv2FfiOpenExtendedMiningChannelSuccess {
                request_id: m.request_id,
                channel_id: m.channel_id,
                target: arr32(&m.target),
                extranonce_size: m.extranonce_size,
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
                group_channel_id: m.group_channel_id,
            },
        },
        AnyMessage::Mining(M::UpdateChannel(m)) => Sv2FfiMessageUnion {
            update_channel: Sv2FfiUpdateChannel {
                channel_id: m.channel_id,
                nominal_hash_rate: m.nominal_hash_rate,
                max_target: arr32(&m.max_target),
            },
        },
        AnyMessage::Mining(M::UpdateChannelError(m)) => Sv2FfiMessageUnion {
            update_channel_error: Sv2FfiUpdateChannelError {
                channel_id: m.channel_id,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::CloseChannel(m)) => Sv2FfiMessageUnion {
            close_channel: Sv2FfiCloseChannel {
                channel_id: m.channel_id,
                reason_code: view(m.reason_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SetExtranoncePrefix(m)) => Sv2FfiMessageUnion {
            set_extranonce_prefix: Sv2FfiSetExtranoncePrefix {
                channel_id: m.channel_id,
                extranonce_prefix: view(m.extranonce_prefix.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SetTarget(m)) => Sv2FfiMessageUnion {
            set_target: Sv2FfiSetTarget {
                channel_id: m.channel_id,
                target: arr32(&m.target),
            },
        },
        AnyMessage::Mining(M::SetGroupChannel(m)) => {
            // mining_sv2 decodes the ids into its own vector, which does not
            // outlive the call; the record points at them in the payload,
            // after the u32 group id and the u16 count.
            let count = m.channel_ids.len();
            Sv2FfiMessageUnion {
                set_group_channel: Sv2FfiSetGroupChannel {
                    group_channel_id: m.group_channel_id,
                    channel_ids_count: count as u16,
                    channel_ids: Sv2FfiBytes {
                        data: core::ptr::null(),
                        len: (count * 4) as u32,
                    },
                },
            }
        }
        AnyMessage::Mining(M::NewMiningJob(m)) => {
            let ntime = m.ntime_start.clone().into_inner();
            Sv2FfiMessageUnion {
                new_mining_job: Sv2FfiNewMiningJob {
                    channel_id: m.channel_id,
                    job_id: m.job_id,
                    has_ntime_start: ntime.is_some(),
                    ntime_start: ntime.unwrap_or(0),
                    version: m.version,
                    merkle_root: arr32(&m.merkle_root),
                },
            }
        }
        AnyMessage::Mining(M::NewExtendedMiningJob(m)) => {
            let (merkle_path_count, merkle_path) = merkle_path_view(m.merkle_path.as_slice())?;
            let ntime = m.ntime_start.clone().into_inner();
            Sv2FfiMessageUnion {
                new_extended_mining_job: Sv2FfiNewExtendedMiningJob {
                    channel_id: m.channel_id,
                    job_id: m.job_id,
                    has_ntime_start: ntime.is_some(),
                    ntime_start: ntime.unwrap_or(0),
                    version: m.version,
                    version_rolling_allowed: m.version_rolling_allowed,
                    merkle_path_count,
                    merkle_path,
                    coinbase_tx_prefix: view(m.coinbase_tx_prefix.as_bytes()),
                    coinbase_tx_suffix: view(m.coinbase_tx_suffix.as_bytes()),
                },
            }
        }
        AnyMessage::Mining(M::SetNewPrevHash(m)) => Sv2FfiMessageUnion {
            set_new_prev_hash_mining: Sv2FfiSetNewPrevHashMining {
                channel_id: m.channel_id,
                job_id: m.job_id,
                prev_hash: arr32(&m.prev_hash),
                ntime_start: m.ntime_start,
                nbits: m.nbits,
            },
        },
        AnyMessage::Mining(M::SetCustomMiningJob(m)) => {
            let (merkle_path_count, merkle_path) = merkle_path_view(m.merkle_path.as_slice())?;
            Sv2FfiMessageUnion {
                set_custom_mining_job: Sv2FfiSetCustomMiningJob {
                    channel_id: m.channel_id,
                    request_id: m.request_id,
                    token: view(m.token.as_bytes()),
                    version: m.version,
                    prev_hash: arr32(&m.prev_hash),
                    ntime_start: m.ntime_start,
                    nbits: m.nbits,
                    coinbase_tx_version: m.coinbase_tx_version,
                    coinbase_prefix: view(m.coinbase_prefix.as_bytes()),
                    coinbase_tx_input_n_sequence: m.coinbase_tx_input_n_sequence,
                    coinbase_tx_outputs: view(m.coinbase_tx_outputs.as_bytes()),
                    coinbase_tx_locktime: m.coinbase_tx_locktime,
                    merkle_path_count,
                    merkle_path,
                },
            }
        }
        AnyMessage::Mining(M::SetCustomMiningJobSuccess(m)) => Sv2FfiMessageUnion {
            set_custom_mining_job_success: Sv2FfiSetCustomMiningJobSuccess {
                channel_id: m.channel_id,
                request_id: m.request_id,
                job_id: m.job_id,
            },
        },
        AnyMessage::Mining(M::SetCustomMiningJobError(m)) => Sv2FfiMessageUnion {
            set_custom_mining_job_error: Sv2FfiSetCustomMiningJobError {
                channel_id: m.channel_id,
                request_id: m.request_id,
                error_code: view(m.error_code.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SubmitSharesStandard(m)) => Sv2FfiMessageUnion {
            submit_shares_standard: Sv2FfiSubmitSharesStandard {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                job_id: m.job_id,
                nonce: m.nonce,
                ntime: m.ntime,
                version: m.version,
            },
        },
        AnyMessage::Mining(M::SubmitSharesExtended(m)) => Sv2FfiMessageUnion {
            submit_shares_extended: Sv2FfiSubmitSharesExtended {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                job_id: m.job_id,
                nonce: m.nonce,
                ntime: m.ntime,
                version: m.version,
                extranonce: view(m.extranonce.as_bytes()),
            },
        },
        AnyMessage::Mining(M::SubmitSharesSuccess(m)) => Sv2FfiMessageUnion {
            submit_shares_success: Sv2FfiSubmitSharesSuccess {
                channel_id: m.channel_id,
                last_sequence_number: m.last_sequence_number,
                new_submits_accepted_count: m.new_submits_accepted_count,
                new_shares_sum: m.new_shares_sum,
            },
        },
        // well-formed, but outside what this API has records for
        AnyMessage::JobDeclaration(_) | AnyMessage::TemplateDistribution(_) | AnyMessage::Extensions(_) => {
            return Err(SV2_FFI_ERR_UNSUPPORTED)
        }
        AnyMessage::Mining(M::SubmitSharesError(m)) => Sv2FfiMessageUnion {
            submit_shares_error: Sv2FfiSubmitSharesError {
                channel_id: m.channel_id,
                sequence_number: m.sequence_number,
                error_code: view(m.error_code.as_bytes()),
            },
        },
    };
    Ok(Sv2FfiMessage { msg_type, u })
}

fn parser_err(e: ParserError) -> i32 {
    match e {
        // a message type or extension the crates do not know
        ParserError::UnexpectedMessage(_) => SV2_FFI_ERR_UNSUPPORTED,
        ParserError::BinaryError(e) => binary_err(e),
        _ => SV2_FFI_ERR_INVALID,
    }
}

/// The message in a frame and its record.  Bytes after the message are
/// left to parsers_sv2, which reads them as the TLV fields of negotiated
/// extensions; none are negotiated here, so they are ignored.
///
/// # Safety
/// `payload` must point at `len` writable bytes that nothing else borrows
/// during the call and that outlive the record, which points into them.
unsafe fn parse(header: Header, payload: *mut u8, len: usize) -> Result<Sv2FfiMessage, i32> {
    // SAFETY: forwarded to the caller; the slice lives for the decode only,
    // so `payload` stays valid for the record's pointers
    let bytes = unsafe { slice::from_raw_parts_mut(payload, len) };
    let msg = AnyMessage::try_from((header, bytes)).map_err(parser_err)?;
    let mut record = to_record(&msg)?;
    // A merkle path's view starts at its first hash, whose borrow reaches
    // that hash alone; the same address through `payload` reaches them all.
    let span = |b: &mut Sv2FfiBytes| {
        let offset = (b.data as usize).wrapping_sub(payload as usize);
        if b.len > 0 && offset < len {
            b.data = payload.wrapping_add(offset);
        }
    };
    match msg {
        AnyMessage::Mining(Mining::SetGroupChannel(_)) => {
            // the ids follow the u32 group id and the u16 count; the decode
            // checked the payload holds them
            record.u.set_group_channel.channel_ids.data = payload.wrapping_add(4 + 2);
        }
        AnyMessage::Mining(Mining::NewExtendedMiningJob(_)) => {
            // SAFETY: to_record() wrote the field of the message it decoded
            span(unsafe { &mut record.u.new_extended_mining_job.merkle_path })
        }
        AnyMessage::Mining(Mining::SetCustomMiningJob(_)) => {
            // SAFETY: as above
            span(unsafe { &mut record.u.set_custom_mining_job.merkle_path })
        }
        _ => {}
    }
    Ok(record)
}

/// Puts back the protocol byte of a SetupConnection decoded with it masked,
/// however the decode ends.
struct RestoreProtocol {
    at: *mut u8,
    raw: u8,
}

impl Drop for RestoreProtocol {
    fn drop(&mut self) {
        // SAFETY: `at` is the first byte of a payload that outlives the
        // guard, and the record's pointers into it derive from `at` too
        unsafe { *self.at = self.raw };
    }
}

/// The record of the message in a frame with `header` and `payload`.
/// `SV2_FFI_ERR_UNSUPPORTED` is a well-formed frame of a message or an
/// extension this API has no record for.
///
/// # Safety
/// The record points into `payload`, which must outlive it and not be
/// borrowed again while the record is in use.
pub(crate) unsafe fn decode(header: Header, payload: &mut [u8]) -> Result<Sv2FfiMessage, i32> {
    // Every pointer into the payload, the record's and the one that puts the
    // protocol byte back, comes from `at`: a borrow of `payload` itself taken
    // after it would invalidate it.
    let (at, len) = (payload.as_mut_ptr(), payload.len());
    // SAFETY: forwarded to the caller
    let r = unsafe { parse(header, at, len) };
    let setup_connection =
        header.ext_type_without_channel_msg() == 0 && header.msg_type() == SV2_FFI_MSG_SETUP_CONNECTION;
    match r {
        // Stopgap: common_messages_sv2 refuses a `protocol` it has no value
        // for instead of decoding the byte, so a role could not answer
        // SetupConnection.Error (unsupported-protocol) as spec §3.6.1
        // requires.  Decode the rest with the byte masked and hand the real
        // value back.  This goes once the crate decodes the byte itself.
        Err(code) if code != SV2_FFI_ERR_UNSUPPORTED && setup_connection && len > 0 => {
            // SAFETY: `at` points at `len` bytes, and `len` is not 0
            let raw = unsafe { *at };
            if Protocol::try_from(raw).is_ok() {
                return Err(code);
            }
            // SAFETY: as above
            unsafe { *at = 0 };
            let _restore = RestoreProtocol { at, raw };
            // SAFETY: forwarded to the caller
            let mut record = unsafe { parse(header, at, len)? };
            record.u.setup_connection.protocol = raw;
            Ok(record)
        }
        r => r,
    }
}

/// A record as the crates' frame, ready to serialize.  AnyMessage itself
/// has no serializer; its two halves do.
enum Plain<'a> {
    Common(MessageFrame<CommonMessages<'a>>),
    Mining(MessageFrame<Mining<'a>>),
}

impl Plain<'_> {
    fn len(&self) -> usize {
        match self {
            Plain::Common(f) => f.encoded_length(),
            Plain::Mining(f) => f.encoded_length(),
        }
    }

    fn into_bytes(self) -> Result<Vec<u8>, i32> {
        let mut out = vec![0u8; self.len()];
        match self {
            Plain::Common(f) => f.encode_into(&mut out),
            Plain::Mining(f) => f.encode_into(&mut out),
        }
        .map_err(|_| SV2_FFI_ERR_INVALID)?;
        Ok(out)
    }
}

/// # Safety
/// Every byte field of the live record must describe readable memory that
/// outlives the returned frame.
unsafe fn plain(m: &Sv2FfiMessage) -> Result<Plain<'_>, i32> {
    // SAFETY: forwarded to the caller
    let msg = unsafe { to_any(m)? };
    let (msg_type, extension, channel) = (msg.message_type(), msg.extension_type(), msg.channel_bit());
    match msg {
        AnyMessage::Common(c) => MessageFrame::from_message(c, msg_type, extension, channel).map(Plain::Common),
        AnyMessage::Mining(c) => MessageFrame::from_message(c, msg_type, extension, channel).map(Plain::Mining),
        _ => return Err(SV2_FFI_ERR_INVALID),
    }
    .map_err(|_| SV2_FFI_ERR_INVALID)
}

/// The plaintext frame length of the record in `m`.  The record is
/// serialized for it, so a record `frame()` refuses is refused here too.
///
/// # Safety
/// Every byte field of the live record must describe readable memory.
pub(crate) unsafe fn frame_len(m: &Sv2FfiMessage) -> Result<usize, i32> {
    // SAFETY: forwarded to the caller
    Ok(unsafe { frame(m)? }.len())
}

/// The plaintext frame of the record in `m`: the header, with the message
/// type and the channel_msg bit its subprotocol crate assigns, then the
/// payload.  A field binary_sv2 does not serialize (a `nominal_hash_rate`
/// that is negative or not finite) is `SV2_FFI_ERR_INVALID`.
///
/// # Safety
/// Every byte field of the live record must describe readable memory.
pub(crate) unsafe fn frame(m: &Sv2FfiMessage) -> Result<Vec<u8>, i32> {
    // SAFETY: forwarded to the caller
    unsafe { plain(m)? }.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SV2_FFI_ERR_INTERNAL, SV2_FFI_ERR_TRUNCATED};

    const H: usize = Header::SIZE;

    fn bytes(s: &[u8]) -> Sv2FfiBytes {
        Sv2FfiBytes::from_slice(s)
    }

    fn encode(m: &Sv2FfiMessage) -> Vec<u8> {
        unsafe { frame(m) }.unwrap_or_else(|e| panic!("encode of type {:#x} gave {e}", m.msg_type))
    }

    /// Decode a plaintext frame whose header may not match its length, as
    /// the session would once the crate's decoder had read `frame.len()`
    /// bytes for it.
    fn decode_frame(frame: &mut [u8]) -> Result<Sv2FfiMessage, i32> {
        let l = ((frame.len() - H) as u32).to_le_bytes();
        let header = Header::from_bytes(&[frame[0], frame[1], frame[2], l[0], l[1], l[2]]).unwrap();
        guard_panic(|| unsafe { decode(header, &mut frame[H..]) })
    }

    fn guard_panic<T>(f: impl FnOnce() -> Result<T, i32>) -> Result<T, i32> {
        crate::ffi::guard(Err(SV2_FFI_ERR_INTERNAL), f)
    }

    fn setup_connection(protocol: u8) -> Sv2FfiMessage {
        Sv2FfiMessage {
            msg_type: SV2_FFI_MSG_SETUP_CONNECTION,
            u: Sv2FfiMessageUnion {
                setup_connection: Sv2FfiSetupConnection {
                    protocol,
                    min_version: 2,
                    max_version: 2,
                    flags: 1,
                    endpoint_host: bytes(b"pool.example.org"),
                    endpoint_port: 3336,
                    vendor: bytes(b"Bitaxe"),
                    hardware_version: bytes(b"BM1370"),
                    firmware: bytes(b"v2.9.0"),
                    device_id: bytes(b""),
                },
            },
        }
    }

    // Every record goes out as a frame and comes back as the same record.
    #[test]
    fn records_round_trip() {
        let target = [0x11u8; 32];
        let prefix = [7u8; 12];
        let path = [9u8; 3 * 32];
        let ids = [1u8, 0, 0, 0, 2, 0, 0, 0];
        let cases = [
            setup_connection(0),
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SETUP_CONNECTION_ERROR,
                u: Sv2FfiMessageUnion {
                    setup_connection_error: Sv2FfiSetupConnectionError {
                        flags: 6,
                        error_code: bytes(b"unsupported-feature-flags"),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL,
                u: Sv2FfiMessageUnion {
                    open_extended_mining_channel: Sv2FfiOpenExtendedMiningChannel {
                        request_id: 10,
                        user_identity: bytes(b"tb1qexample.bitaxe"),
                        nominal_hash_rate: 5.5e11,
                        max_target: target,
                        min_extranonce_size: 8,
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                u: Sv2FfiMessageUnion {
                    open_extended_mining_channel_success: Sv2FfiOpenExtendedMiningChannelSuccess {
                        request_id: 10,
                        channel_id: 5,
                        target,
                        extranonce_size: 8,
                        extranonce_prefix: bytes(&prefix[..4]),
                        group_channel_id: 1,
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SET_GROUP_CHANNEL,
                u: Sv2FfiMessageUnion {
                    set_group_channel: Sv2FfiSetGroupChannel {
                        group_channel_id: 1,
                        channel_ids_count: 2,
                        channel_ids: bytes(&ids),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB,
                u: Sv2FfiMessageUnion {
                    new_extended_mining_job: Sv2FfiNewExtendedMiningJob {
                        channel_id: 5,
                        job_id: 7,
                        has_ntime_start: true,
                        ntime_start: 1_760_000_000,
                        version: 0x2000_0000,
                        version_rolling_allowed: true,
                        merkle_path_count: 3,
                        merkle_path: bytes(&path),
                        coinbase_tx_prefix: bytes(&[1u8; 2048]),
                        coinbase_tx_suffix: bytes(&[2u8; 300]),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SET_NEW_PREV_HASH_MINING,
                u: Sv2FfiMessageUnion {
                    set_new_prev_hash_mining: Sv2FfiSetNewPrevHashMining {
                        channel_id: 5,
                        job_id: 7,
                        prev_hash: target,
                        ntime_start: 1_760_000_000,
                        nbits: 0x1703_1abe,
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SET_CUSTOM_MINING_JOB,
                u: Sv2FfiMessageUnion {
                    set_custom_mining_job: Sv2FfiSetCustomMiningJob {
                        channel_id: 5,
                        request_id: 3,
                        token: bytes(b"declared-job-token"),
                        version: 0x2000_0000,
                        prev_hash: target,
                        ntime_start: 1_760_000_000,
                        nbits: 0x1703_1abe,
                        coinbase_tx_version: 2,
                        coinbase_prefix: bytes(&[3, 0x10, 0x20, 0x30]),
                        coinbase_tx_input_n_sequence: 0xffff_ffff,
                        coinbase_tx_outputs: bytes(&[4u8; 120]),
                        coinbase_tx_locktime: 0,
                        merkle_path_count: 3,
                        merkle_path: bytes(&path),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS,
                u: Sv2FfiMessageUnion {
                    set_custom_mining_job_success: Sv2FfiSetCustomMiningJobSuccess {
                        channel_id: 5,
                        request_id: 3,
                        job_id: 9,
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR,
                u: Sv2FfiMessageUnion {
                    set_custom_mining_job_error: Sv2FfiSetCustomMiningJobError {
                        channel_id: 5,
                        request_id: 3,
                        error_code: bytes(b"invalid-mining-job-token"),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SUBMIT_SHARES_EXTENDED,
                u: Sv2FfiMessageUnion {
                    submit_shares_extended: Sv2FfiSubmitSharesExtended {
                        channel_id: 5,
                        sequence_number: 2,
                        job_id: 8,
                        nonce: 0x1234_5678,
                        ntime: 1_760_000_003,
                        version: 0x20a0_0000,
                        extranonce: bytes(&[3u8; 8]),
                    },
                },
            },
            Sv2FfiMessage {
                msg_type: SV2_FFI_MSG_SUBMIT_SHARES_SUCCESS,
                u: Sv2FfiMessageUnion {
                    submit_shares_success: Sv2FfiSubmitSharesSuccess {
                        channel_id: 5,
                        last_sequence_number: 2,
                        new_submits_accepted_count: 2,
                        new_shares_sum: 0x1_0000_0002,
                    },
                },
            },
        ];
        for m in &cases {
            let mut frame = encode(m);
            let back = decode_frame(&mut frame).unwrap_or_else(|e| panic!("type {:#x}: {e}", m.msg_type));
            assert_eq!(back.msg_type, m.msg_type);
            let again = encode(&back);
            assert_eq!(again, frame, "type {:#x}", m.msg_type);
            // a byte too many is left to the crate, which ignores it; one
            // too few is an error
            frame.push(0);
            let back = decode_frame(&mut frame).unwrap_or_else(|e| panic!("type {:#x} and a byte: {e}", m.msg_type));
            assert_eq!(encode(&back), again, "type {:#x}", m.msg_type);
            frame.truncate(frame.len() - 2);
            assert!(decode_frame(&mut frame).is_err(), "type {:#x}", m.msg_type);
            // and no damage to a valid frame makes the crates panic
            frame.pop();
            frame.pop();
            let mut rng = XorShift(0x5eed ^ m.msg_type as u64);
            for _ in 0..2000 {
                let mut bad = frame.clone();
                mutate(&mut rng, &mut bad);
                if bad.len() >= H {
                    assert_ne!(
                        decode_frame(&mut bad).err(),
                        Some(SV2_FFI_ERR_INTERNAL),
                        "type {:#x}",
                        m.msg_type
                    );
                }
            }
        }
    }

    /// A small deterministic generator, so a failure replays.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Flip, overwrite, insert or cut bytes of a frame.
    fn mutate(rng: &mut XorShift, f: &mut Vec<u8>) {
        for _ in 0..1 + rng.below(4) {
            let i = rng.below(f.len().max(1));
            match rng.below(5) {
                0 if !f.is_empty() => f[i] ^= 1 << rng.below(8),
                1 if !f.is_empty() => f[i] = rng.next() as u8,
                2 => f.insert(i.min(f.len()), rng.next() as u8),
                3 if !f.is_empty() => f.truncate(i),
                _ => {
                    let extra = rng.below(40);
                    for _ in 0..extra {
                        f.push(rng.next() as u8);
                    }
                }
            }
        }
    }

    // Random payloads under every message type, with and without the
    // channel_msg bit and under extensions: whatever the verdict, it is not
    // a panic, and what decodes re-encodes without one.
    #[test]
    fn random_payloads_never_panic() {
        let mut rng = XorShift(0x000c_3a17);
        let mut frame = vec![0u8; H + 512];
        for ext in [0u16, 0x8000, 0x0001, 0x0002, 0x8002] {
            for msg_type in 0..=255u8 {
                for _ in 0..40 {
                    let len = rng.below(512);
                    frame[..2].copy_from_slice(&ext.to_le_bytes());
                    frame[2] = msg_type;
                    for b in frame[H..H + len].iter_mut() {
                        *b = rng.next() as u8;
                    }
                    let r = decode_frame(&mut frame[..H + len]);
                    assert_ne!(
                        r.err(),
                        Some(SV2_FFI_ERR_INTERNAL),
                        "ext {ext:#x} type {msg_type:#x} len {len}"
                    );
                    if let Ok(m) = r {
                        let again = guard_panic(|| unsafe { super::frame(&m) });
                        assert_ne!(
                            again.err(),
                            Some(SV2_FFI_ERR_INTERNAL),
                            "re-encode of type {msg_type:#x}"
                        );
                    }
                }
            }
        }
    }

    // binary_sv2 refuses to serialize a hash rate that is negative or not
    // finite, so the encoder has no frame for one.  The decoder hands over
    // whatever a peer sent: the channel is what refuses it.
    #[test]
    fn a_hash_rate_that_is_not_one_does_not_encode() {
        let open = |rate: f32| Sv2FfiMessage {
            msg_type: SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL,
            u: Sv2FfiMessageUnion {
                open_standard_mining_channel: Sv2FfiOpenStandardMiningChannel {
                    request_id: 1,
                    user_identity: bytes(b"worker"),
                    nominal_hash_rate: rate,
                    max_target: [0xff; 32],
                },
            },
        };
        let extended = |rate: f32| Sv2FfiMessage {
            msg_type: SV2_FFI_MSG_OPEN_EXTENDED_MINING_CHANNEL,
            u: Sv2FfiMessageUnion {
                open_extended_mining_channel: Sv2FfiOpenExtendedMiningChannel {
                    request_id: 1,
                    user_identity: bytes(b"worker"),
                    nominal_hash_rate: rate,
                    max_target: [0xff; 32],
                    min_extranonce_size: 8,
                },
            },
        };
        let update = |rate: f32| Sv2FfiMessage {
            msg_type: SV2_FFI_MSG_UPDATE_CHANNEL,
            u: Sv2FfiMessageUnion {
                update_channel: Sv2FfiUpdateChannel {
                    channel_id: 1,
                    nominal_hash_rate: rate,
                    max_target: [0xff; 32],
                },
            },
        };
        for rate in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0, -0.0] {
            for m in [open(rate), extended(rate), update(rate)] {
                assert_eq!(
                    unsafe { frame(&m) }.err(),
                    Some(SV2_FFI_ERR_INVALID),
                    "type {:#x}, {rate}",
                    m.msg_type
                );
            }
        }
        for rate in [0.0, f32::MIN_POSITIVE, 1.0e12, f32::MAX] {
            for m in [open(rate), extended(rate), update(rate)] {
                assert!(unsafe { frame(&m) }.is_ok(), "type {:#x}, {rate}", m.msg_type);
            }
        }
        // on the wire the field follows request_id and the identity
        let mut frame = encode(&open(1.0e12));
        let at = H + 4 + 1 + b"worker".len();
        assert_eq!(frame[at..at + 4], 1.0e12f32.to_le_bytes());
        frame[at..at + 4].copy_from_slice(&f32::NAN.to_le_bytes());
        let m = decode_frame(&mut frame).expect("decodes");
        assert!(unsafe { m.u.open_standard_mining_channel.nominal_hash_rate }.is_nan());
    }

    // An unknown protocol must reach the role, so it can answer
    // SetupConnection.Error (spec §3.6.1).
    #[test]
    fn setup_connection_with_an_unknown_protocol_decodes() {
        let mut frame = encode(&setup_connection(0));
        frame[H] = 3;
        let m = decode_frame(&mut frame).expect("decodes");
        assert_eq!(m.msg_type, SV2_FFI_MSG_SETUP_CONNECTION);
        let c = unsafe { m.u.setup_connection };
        assert_eq!((c.protocol, c.min_version, c.endpoint_port), (3, 2, 3336));
        assert_eq!(unsafe { c.vendor.as_slice() }.unwrap(), b"Bitaxe");
        assert_eq!(frame[H], 3, "the payload is left as it was");
        // cut short, it fails like any other, and the byte is still put back
        let n = frame.len();
        assert_eq!(decode_frame(&mut frame[..n - 1]).err(), Some(SV2_FFI_ERR_TRUNCATED));
        assert_eq!(frame[H], 3);
        // the encoder has no byte to put on the wire for it
        assert_eq!(
            unsafe { super::frame(&setup_connection(3)) }.err(),
            Some(SV2_FFI_ERR_INVALID)
        );
    }

    // What follows a message is parsers_sv2's to read, as TLV fields of the
    // negotiated extensions; with none negotiated, nothing after the message
    // changes the verdict.
    #[test]
    fn bytes_after_the_message_are_left_to_parsers_sv2() {
        let base = encode(&setup_connection(0));
        // worker identity, extension 0x0002, field 1, "rig1"
        let mut with_tlv = base.clone();
        with_tlv.extend_from_slice(&[0x02, 0x00, 0x01, 0x04, 0x00, b'r', b'i', b'g', b'1']);
        let mut garbage = base.clone();
        garbage.extend_from_slice(&[0x02, 0x00, 0x01, 0x09, 0x00, b'r']);
        for mut frame in [with_tlv, garbage] {
            let m = decode_frame(&mut frame).expect("decodes");
            assert_eq!(encode(&m), base);
        }
    }

    // Dispatch is the crate's: unknown types and extensions are reported as
    // such, and the channel_msg bit of a frame is not compared with the
    // message's, as parsers_sv2 does not.
    #[test]
    fn dispatch_follows_parsers_sv2() {
        let mut unknown = encode(&setup_connection(0));
        unknown[2] = 0x7f;
        assert_eq!(decode_frame(&mut unknown).err(), Some(SV2_FFI_ERR_UNSUPPORTED));
        let mut extension = encode(&setup_connection(0));
        extension[0] = 0x05;
        assert_eq!(decode_frame(&mut extension).err(), Some(SV2_FFI_ERR_UNSUPPORTED));
        // RequestExtensions: extension 1, type 0; request_id 1 then one
        // requested extension, 0x0002
        let mut request = vec![0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00];
        assert_eq!(decode_frame(&mut request).err(), Some(SV2_FFI_ERR_UNSUPPORTED));
        let mut wrong_bit = encode(&setup_connection(0));
        wrong_bit[1] |= 0x80;
        assert_eq!(
            decode_frame(&mut wrong_bit).map(|m| m.msg_type),
            Ok(SV2_FFI_MSG_SETUP_CONNECTION)
        );
    }
}
