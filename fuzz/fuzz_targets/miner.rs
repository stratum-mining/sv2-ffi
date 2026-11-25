// The other end of a connection, for the targets that need a peer to send
// frames the C API would never encode: a codec_sv2 initiator, used as SRI
// roles use it, through the handshake with a C responder.

// each target uses the part of it it needs
#![allow(dead_code)]

use codec_sv2::{
    Decrypted, EncodableFrame, Handshake, NoiseDecoder, NoiseEncoder, TransportDecryptState, TransportEncryptState,
};
use noise_sv2::Initiator;
use sv2_ffi::*;

/// A plaintext frame, header included, handed to the encoder as is.
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

pub struct Miner {
    encrypt: TransportEncryptState,
    decrypt: Option<TransportDecryptState>,
    encoder: NoiseEncoder,
    decoder: NoiseDecoder,
}

impl Miner {
    /// Run the handshake with `server`, a fresh responder of the authority
    /// `pk`.
    ///
    /// # Safety
    /// `server` must be a live session.
    pub unsafe fn connect(server: *mut Sv2FfiNoise, pk: &[u8; 32], now: u32) -> Self {
        let h = Handshake::initiator(Initiator::from_raw_k(*pk).unwrap());
        let (act1, h) = h.step_0().unwrap();
        let mut act2 = [0u8; SV2_FFI_ACT2_SIZE];
        assert_eq!(
            unsafe { sv2_ffi_noise_responder_step1(server, act1.payload().as_ptr(), now, act2.as_mut_ptr()) },
            SV2_FFI_OK
        );
        let (encrypt, decrypt) = h.step_2_with_now(act2, now).unwrap().split();
        Miner {
            encrypt,
            decrypt: Some(decrypt),
            encoder: NoiseEncoder::new(),
            decoder: NoiseDecoder::new(),
        }
    }

    /// The wire bytes of a plaintext frame, or None for one the encoder
    /// refuses (a header that does not match its length).
    pub fn send(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let wire = self.encoder.encode_transport(Raw(frame), &mut self.encrypt).ok()?;
        let wire: &[u8] = wire.as_ref();
        Some(wire.to_vec())
    }

    /// The plaintext frame in `wire`, which holds exactly one.
    pub fn receive(&mut self, mut wire: &[u8]) -> Vec<u8> {
        loop {
            let want = self.decoder.read_len();
            let take = want.min(wire.len());
            self.decoder.read_buf()[..take].copy_from_slice(&wire[..take]);
            self.decoder.advance(take).unwrap();
            wire = &wire[take..];
            match self.decoder.next_transport_frame(self.decrypt.take().unwrap()).unwrap() {
                Decrypted::Frame(frame, state) => {
                    self.decrypt = Some(state);
                    assert!(wire.is_empty(), "more than one frame");
                    return frame.as_bytes().to_vec();
                }
                Decrypted::Incomplete(state) => self.decrypt = Some(state),
            }
        }
    }
}

/// A plaintext frame: the header the input chose, with the real length.
pub fn frame(extension_type: u16, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = extension_type.to_le_bytes().to_vec();
    f.push(msg_type);
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
    f.extend_from_slice(payload);
    f
}

/// One authority for every run.
pub fn authority() -> &'static ([u8; 32], [u8; 32]) {
    static KEYS: std::sync::OnceLock<([u8; 32], [u8; 32])> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let (mut sk, mut pk) = ([0u8; 32], [0u8; 32]);
        assert_eq!(
            unsafe { sv2_ffi_authority_keypair_generate(sk.as_mut_ptr(), pk.as_mut_ptr()) },
            SV2_FFI_OK
        );
        (sk, pk)
    })
}
