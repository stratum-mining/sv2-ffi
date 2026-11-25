/*
 * The C API on its own: a C program that links only libsv2_ffi and runs
 * each group of sv2_ffi.h the way a server and a miner would, with the
 * error paths a C caller relies on.  Nothing else is linked, so the library
 * can be checked wherever it is built:
 *
 *   ./test.sh          (builds the library, runs cargo test and this)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sv2_ffi.h>

static int failures;

#define CHECK(cond)                                                                         \
	do {                                                                                    \
		if (!(cond)) {                                                                      \
			fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond);        \
			failures++;                                                                     \
		}                                                                                   \
	} while (0)

#define CHECK_EQ(a, b)                                                                      \
	do {                                                                                    \
		long long a_ = (long long)(a), b_ = (long long)(b);                                 \
		if (a_ != b_) {                                                                     \
			fprintf(stderr, "%s:%d: %s is %lld, expected %lld\n", __FILE__, __LINE__, #a, a_, b_); \
			failures++;                                                                     \
		}                                                                                   \
	} while (0)

static Sv2FfiBytes bytes(const void *p, size_t len) {
	Sv2FfiBytes b;
	b.data = (const uint8_t *)p;
	b.len = (uint32_t)len;
	return b;
}

static int bytes_eq(Sv2FfiBytes b, const void *p, size_t len) {
	return b.len == len && (len == 0 || memcmp(b.data, p, len) == 0);
}

static int str_eq(Sv2FfiBytes b, const char *s) {
	return bytes_eq(b, s, strlen(s));
}

static uint8_t authority_sk[32], authority_pk[32];

static void test_keys(void) {
	uint8_t pk[32], other_sk[32], other_pk[32];
	char text[SV2_FFI_AUTHORITY_BASE58_MAX];
	int n;

	CHECK_EQ(sv2_ffi_authority_keypair_generate(authority_sk, authority_pk), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_authority_pubkey(authority_sk, pk), SV2_FFI_OK);
	CHECK(memcmp(pk, authority_pk, 32) == 0);
	CHECK_EQ(sv2_ffi_authority_keypair_generate(other_sk, other_pk), SV2_FFI_OK);
	CHECK(memcmp(other_pk, authority_pk, 32) != 0);

	n = sv2_ffi_authority_pubkey_to_base58(authority_pk, text, sizeof(text));
	CHECK(n > 0 && (size_t)n == strlen(text));
	memset(pk, 0, sizeof(pk));
	CHECK_EQ(sv2_ffi_authority_pubkey_from_base58(text, pk), SV2_FFI_OK);
	CHECK(memcmp(pk, authority_pk, 32) == 0);
	CHECK_EQ(sv2_ffi_authority_pubkey_to_base58(authority_pk, text, 8), SV2_FFI_ERR_OVERFLOW);
	CHECK_EQ(sv2_ffi_authority_pubkey_from_base58("9notbase58!", pk), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_authority_pubkey_from_base58(NULL, pk), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_authority_pubkey(NULL, pk), SV2_FFI_ERR_INVALID);
}

// A responder and an initiator through the three acts: the certificate is
// signed at `signed_at` and checked at `checked_at`.
static int handshake_at(struct Sv2FfiNoise **server, struct Sv2FfiNoise **miner, const uint8_t *pinned,
                        uint32_t validity, uint32_t signed_at, uint32_t checked_at) {
	uint8_t act1[SV2_FFI_ACT1_SIZE], act2[SV2_FFI_ACT2_SIZE];
	int r;

	*server = sv2_ffi_noise_responder_new(authority_pk, authority_sk, validity);
	*miner = sv2_ffi_noise_initiator_new(pinned);
	if (!*server || !*miner) return SV2_FFI_ERR_INVALID;
	if ((r = sv2_ffi_noise_initiator_step0(*miner, act1)) != SV2_FFI_OK) return r;
	if ((r = sv2_ffi_noise_responder_step1(*server, act1, signed_at, act2)) != SV2_FFI_OK) return r;
	return sv2_ffi_noise_initiator_step2(*miner, act2, checked_at);
}

static int handshake(struct Sv2FfiNoise **server, struct Sv2FfiNoise **miner, const uint8_t *pinned) {
	uint32_t now = (uint32_t)time(NULL);
	return handshake_at(server, miner, pinned, 3600, now, now);
}

static void test_handshake(void) {
	struct Sv2FfiNoise *server, *miner;
	uint8_t other_sk[32], other_pk[32], act1[SV2_FFI_ACT1_SIZE], act2[SV2_FFI_ACT2_SIZE], wire[256];
	uint32_t now = (uint32_t)time(NULL), consumed = 99;
	Sv2FfiMessage m;

	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_FFI_OK);
	CHECK(sv2_ffi_noise_is_transport(server));
	CHECK(sv2_ffi_noise_is_transport(miner));
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);

	// pinned to another authority, or checked past its validity, the
	// certificate is refused
	CHECK_EQ(sv2_ffi_authority_keypair_generate(other_sk, other_pk), SV2_FFI_OK);
	CHECK_EQ(handshake(&server, &miner, other_pk), SV2_FFI_ERR_CERT);
	CHECK(!sv2_ffi_noise_is_transport(miner));
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);
	CHECK_EQ(handshake_at(&server, &miner, authority_pk, 60, now, now + 3600), SV2_FFI_ERR_CERT);
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);
	// a zero validity is the crate's: only its leeway around `now`
	CHECK_EQ(handshake_at(&server, &miner, authority_pk, 0, now, now), SV2_FFI_OK);
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);

	// no pinned key, a key pair that does not match, a missing key: no session
	CHECK(sv2_ffi_noise_initiator_new(NULL) == NULL);
	CHECK(sv2_ffi_noise_responder_new(other_pk, authority_sk, 3600) == NULL);
	CHECK(sv2_ffi_noise_responder_new(NULL, authority_sk, 3600) == NULL);
	sv2_ffi_noise_free(NULL);
	CHECK(!sv2_ffi_noise_is_transport(NULL));

	// each step only in its place, and no message before the handshake
	server = sv2_ffi_noise_responder_new(authority_pk, authority_sk, 3600);
	miner = sv2_ffi_noise_initiator_new(authority_pk);
	CHECK(server != NULL && miner != NULL);
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SETUP_CONNECTION_SUCCESS;
	CHECK_EQ(sv2_ffi_noise_encode(miner, &m, wire, sizeof(wire)), SV2_FFI_ERR_STATE);
	consumed = 99;
	CHECK_EQ(sv2_ffi_noise_try_decode(server, wire, 10, &consumed, &m), SV2_FFI_ERR_STATE);
	CHECK_EQ(consumed, 0);
	CHECK_EQ(sv2_ffi_noise_initiator_step0(server, act1), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_initiator_step0(miner, act1), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_noise_initiator_step0(miner, act1), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_responder_step1(miner, act1, now, act2), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_initiator_step2(server, act2, now), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_responder_step1(server, act1, now, act2), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_noise_responder_step1(server, act1, now, act2), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_initiator_step2(miner, act2, now), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_noise_initiator_step2(miner, act2, now), SV2_FFI_ERR_STATE);
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);
}

// Encode `m` on `from` and hand the wire bytes to `to` in pieces of `step`
// bytes; returns what the last try_decode returned, with the record in
// `back`.
static int send_msg(struct Sv2FfiNoise *from, struct Sv2FfiNoise *to, const Sv2FfiMessage *m, uint32_t step,
                    int tamper, Sv2FfiMessage *back) {
	int size = sv2_ffi_noise_encoded_size(m), n, r = SV2_FFI_NEED_MORE;
	uint32_t off = 0;
	uint8_t *wire;

	if (size < 0) return size;
	wire = malloc((size_t)size);
	if (!wire) return SV2_FFI_ERR_OVERFLOW;
	n = sv2_ffi_noise_encode(from, m, wire, (uint32_t)size);
	if (n != size) {
		free(wire);
		return n < 0 ? n : SV2_FFI_ERR_INVALID;
	}
	if (tamper) wire[n - 1] ^= 1;
	while (off < (uint32_t)n && r == SV2_FFI_NEED_MORE) {
		uint32_t piece = (uint32_t)n - off < step ? (uint32_t)n - off : step, consumed = 0;
		r = sv2_ffi_noise_try_decode(to, wire + off, piece, &consumed, back);
		off += consumed;
		if (r == SV2_FFI_NEED_MORE && consumed != piece) r = SV2_FFI_ERR_STATE;
	}
	// a message ends where its bytes do
	if (r == SV2_FFI_OK && off != (uint32_t)n) r = SV2_FFI_ERR_STATE;
	free(wire);
	return r;
}

static void test_transport_and_messages(void) {
	struct Sv2FfiNoise *server, *miner;
	uint8_t wire[4096], target[32], path[2 * 32], prefix[300], suffix[40], outputs[60];
	static const uint8_t ids[] = {7, 0, 0, 0, 9, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
	Sv2FfiMessage m, back;
	uint32_t consumed;
	int a, b;

	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_FFI_OK);

	// SetupConnection, miner to server, fed a byte at a time
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SETUP_CONNECTION;
	m.u.setup_connection.protocol = 0;
	m.u.setup_connection.min_version = 2;
	m.u.setup_connection.max_version = 2;
	m.u.setup_connection.flags = 1;
	m.u.setup_connection.endpoint_host = bytes("pool.example.org", 16);
	m.u.setup_connection.endpoint_port = 3336;
	m.u.setup_connection.vendor = bytes("capi_test", 9);
	m.u.setup_connection.hardware_version = bytes("", 0);
	m.u.setup_connection.firmware = bytes("1.0", 3);
	m.u.setup_connection.device_id = bytes("", 0);
	CHECK_EQ(send_msg(miner, server, &m, 1, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.msg_type, SV2_FFI_MSG_SETUP_CONNECTION);
	CHECK_EQ(back.u.setup_connection.endpoint_port, 3336);
	CHECK(str_eq(back.u.setup_connection.vendor, "capi_test"));
	CHECK(str_eq(back.u.setup_connection.endpoint_host, "pool.example.org"));

	// what the encoder refuses leaves the session as it was
	CHECK_EQ(sv2_ffi_noise_encode(miner, &m, wire, 10), SV2_FFI_ERR_OVERFLOW);
	CHECK_EQ(sv2_ffi_noise_encode(miner, NULL, wire, sizeof(wire)), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_noise_encode(miner, &m, NULL, sizeof(wire)), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_noise_encode(NULL, &m, wire, sizeof(wire)), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_noise_encoded_size(NULL), SV2_FFI_ERR_INVALID);
	back = m;
	back.msg_type = 0x7f;
	CHECK_EQ(sv2_ffi_noise_encoded_size(&back), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_noise_encode(miner, &back, wire, sizeof(wire)), SV2_FFI_ERR_INVALID);
	back = m;
	back.u.setup_connection.vendor = bytes(NULL, 5);
	CHECK_EQ(sv2_ffi_noise_encode(miner, &back, wire, sizeof(wire)), SV2_FFI_ERR_INVALID);
	m.msg_type = SV2_FFI_MSG_OPEN_STANDARD_MINING_CHANNEL;
	memset(&m.u.open_standard_mining_channel, 0, sizeof(m.u.open_standard_mining_channel));
	m.u.open_standard_mining_channel.user_identity = bytes("worker", 6);
	m.u.open_standard_mining_channel.nominal_hash_rate = -1.0f;
	CHECK_EQ(sv2_ffi_noise_encoded_size(&m), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_noise_encode(miner, &m, wire, sizeof(wire)), SV2_FFI_ERR_INVALID);
	// and so does what the decoder refuses; empty input needs more
	consumed = 99;
	CHECK_EQ(sv2_ffi_noise_try_decode(server, NULL, 0, &consumed, &back), SV2_FFI_NEED_MORE);
	CHECK_EQ(consumed, 0);
	// a NULL argument uses nothing, and *consumed says so
	consumed = 99;
	CHECK_EQ(sv2_ffi_noise_try_decode(server, NULL, 10, &consumed, &back), SV2_FFI_ERR_INVALID);
	CHECK_EQ(consumed, 0);
	CHECK_EQ(sv2_ffi_noise_try_decode(server, wire, 10, NULL, &back), SV2_FFI_ERR_INVALID);
	consumed = 99;
	CHECK_EQ(sv2_ffi_noise_try_decode(server, wire, 10, &consumed, NULL), SV2_FFI_ERR_INVALID);
	CHECK_EQ(consumed, 0);
	consumed = 99;
	CHECK_EQ(sv2_ffi_noise_try_decode(NULL, wire, 10, &consumed, &back), SV2_FFI_ERR_INVALID);
	CHECK_EQ(consumed, 0);
	CHECK(sv2_ffi_noise_is_transport(server));

	// SetTarget, server to miner, in one piece
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SET_TARGET;
	m.u.set_target.channel_id = 7;
	memset(target, 0xff, 32);
	target[31] = 0x00;
	memcpy(m.u.set_target.target, target, 32);
	CHECK_EQ(send_msg(server, miner, &m, 4096, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.msg_type, SV2_FFI_MSG_SET_TARGET);
	CHECK_EQ(back.u.set_target.channel_id, 7);
	CHECK(memcmp(back.u.set_target.target, target, 32) == 0);

	// the two records whose byte ranges the library computes: a merkle
	// path and a list of channel ids
	memset(path, 0x5a, sizeof(path));
	path[32] = 0xa5;
	memset(prefix, 1, sizeof(prefix));
	memset(suffix, 2, sizeof(suffix));
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB;
	m.u.new_extended_mining_job.channel_id = 7;
	m.u.new_extended_mining_job.job_id = 3;
	m.u.new_extended_mining_job.version = 0x20000000;
	m.u.new_extended_mining_job.version_rolling_allowed = true;
	m.u.new_extended_mining_job.merkle_path_count = 2;
	m.u.new_extended_mining_job.merkle_path = bytes(path, sizeof(path));
	m.u.new_extended_mining_job.coinbase_tx_prefix = bytes(prefix, sizeof(prefix));
	m.u.new_extended_mining_job.coinbase_tx_suffix = bytes(suffix, sizeof(suffix));
	CHECK_EQ(send_msg(server, miner, &m, 7, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.msg_type, SV2_FFI_MSG_NEW_EXTENDED_MINING_JOB);
	CHECK(!back.u.new_extended_mining_job.has_ntime_start);
	CHECK_EQ(back.u.new_extended_mining_job.merkle_path_count, 2);
	CHECK(bytes_eq(back.u.new_extended_mining_job.merkle_path, path, sizeof(path)));
	CHECK(bytes_eq(back.u.new_extended_mining_job.coinbase_tx_prefix, prefix, sizeof(prefix)));
	CHECK(bytes_eq(back.u.new_extended_mining_job.coinbase_tx_suffix, suffix, sizeof(suffix)));
	// a path that does not match its count is refused
	m.u.new_extended_mining_job.merkle_path_count = 3;
	CHECK_EQ(sv2_ffi_noise_encoded_size(&m), SV2_FFI_ERR_INVALID);
	// a job with only the coinbase: an empty path encodes from NULL and
	// decodes to a pointer memcpy takes
	m.u.new_extended_mining_job.merkle_path_count = 0;
	m.u.new_extended_mining_job.merkle_path = bytes(NULL, 0);
	CHECK_EQ(send_msg(server, miner, &m, 4096, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.u.new_extended_mining_job.merkle_path_count, 0);
	CHECK_EQ(back.u.new_extended_mining_job.merkle_path.len, 0);
	CHECK(back.u.new_extended_mining_job.merkle_path.data != NULL);
	memcpy(path, back.u.new_extended_mining_job.merkle_path.data, back.u.new_extended_mining_job.merkle_path.len);

	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SET_GROUP_CHANNEL;
	m.u.set_group_channel.group_channel_id = 1;
	m.u.set_group_channel.channel_ids_count = 3;
	m.u.set_group_channel.channel_ids = bytes(ids, sizeof(ids));
	CHECK_EQ(send_msg(server, miner, &m, 4096, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.msg_type, SV2_FFI_MSG_SET_GROUP_CHANNEL);
	CHECK_EQ(back.u.set_group_channel.channel_ids_count, 3);
	CHECK(bytes_eq(back.u.set_group_channel.channel_ids, ids, sizeof(ids)));

	// SetCustomMiningJob, miner (a job declarator client) to server
	memset(outputs, 4, sizeof(outputs));
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SET_CUSTOM_MINING_JOB;
	m.u.set_custom_mining_job.channel_id = 7;
	m.u.set_custom_mining_job.request_id = 11;
	m.u.set_custom_mining_job.token = bytes("token", 5);
	m.u.set_custom_mining_job.version = 0x20000000;
	memcpy(m.u.set_custom_mining_job.prev_hash, target, 32);
	m.u.set_custom_mining_job.ntime_start = 1700000000;
	m.u.set_custom_mining_job.nbits = 0x1d00ffff;
	m.u.set_custom_mining_job.coinbase_tx_version = 2;
	m.u.set_custom_mining_job.coinbase_prefix = bytes("\x03\x10\x20\x30", 4);
	m.u.set_custom_mining_job.coinbase_tx_input_n_sequence = 0xffffffff;
	m.u.set_custom_mining_job.coinbase_tx_outputs = bytes(outputs, sizeof(outputs));
	m.u.set_custom_mining_job.merkle_path_count = 2;
	m.u.set_custom_mining_job.merkle_path = bytes(path, sizeof(path));
	CHECK_EQ(send_msg(miner, server, &m, 13, 0, &back), SV2_FFI_OK);
	CHECK_EQ(back.msg_type, SV2_FFI_MSG_SET_CUSTOM_MINING_JOB);
	CHECK_EQ(back.u.set_custom_mining_job.request_id, 11);
	CHECK(str_eq(back.u.set_custom_mining_job.token, "token"));
	CHECK(bytes_eq(back.u.set_custom_mining_job.coinbase_tx_outputs, outputs, sizeof(outputs)));
	CHECK(bytes_eq(back.u.set_custom_mining_job.merkle_path, path, sizeof(path)));

	// two messages in one read: the first leaves the second's bytes
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS;
	m.u.set_custom_mining_job_success.channel_id = 7;
	m.u.set_custom_mining_job_success.request_id = 11;
	m.u.set_custom_mining_job_success.job_id = 4;
	a = sv2_ffi_noise_encode(server, &m, wire, sizeof(wire));
	CHECK(a > 0);
	m.msg_type = SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR;
	m.u.set_custom_mining_job_error.channel_id = 7;
	m.u.set_custom_mining_job_error.request_id = 12;
	m.u.set_custom_mining_job_error.error_code = bytes("invalid-mining-job-token", 24);
	b = a > 0 ? sv2_ffi_noise_encode(server, &m, wire + a, sizeof(wire) - (uint32_t)a) : -1;
	CHECK(b > 0);
	if (a > 0 && b > 0) {
		CHECK_EQ(sv2_ffi_noise_try_decode(miner, wire, (uint32_t)(a + b), &consumed, &back), SV2_FFI_OK);
		CHECK_EQ(consumed, a);
		CHECK_EQ(back.msg_type, SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_SUCCESS);
		CHECK_EQ(back.u.set_custom_mining_job_success.job_id, 4);
		CHECK_EQ(sv2_ffi_noise_try_decode(miner, wire + a, (uint32_t)b, &consumed, &back), SV2_FFI_OK);
		CHECK_EQ(consumed, b);
		CHECK_EQ(back.msg_type, SV2_FFI_MSG_SET_CUSTOM_MINING_JOB_ERROR);
		CHECK(str_eq(back.u.set_custom_mining_job_error.error_code, "invalid-mining-job-token"));
	}
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);

	// a flipped bit on the wire fails the tag and ends the session: nothing
	// works on it after that
	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_FFI_OK);
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_FFI_MSG_SET_TARGET;
	CHECK_EQ(send_msg(server, miner, &m, 4096, 1, &back), SV2_FFI_ERR_CRYPTO);
	CHECK(!sv2_ffi_noise_is_transport(miner));
	CHECK_EQ(sv2_ffi_noise_encode(miner, &m, wire, sizeof(wire)), SV2_FFI_ERR_STATE);
	CHECK_EQ(sv2_ffi_noise_try_decode(miner, wire, 30, &consumed, &back), SV2_FFI_ERR_STATE);
	sv2_ffi_noise_free(server);
	sv2_ffi_noise_free(miner);
}

// A coinbase around a 12 byte extranonce slot in its scriptSig, split at
// the slot (the same one as the crate's own channel tests).
static const uint8_t cb_prefix[] = {
	1, 0, 0, 0, 1,                                                                         // version, one input
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // prevout hash
	0xff, 0xff, 0xff, 0xff,                                                                // prevout index
	16, 3, 0x10, 0x20, 0x30,                                                               // scriptSig: height push, then the slot
};
static const uint8_t cb_suffix[] = {
	0xff, 0xff, 0xff, 0xff,          // sequence
	1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x51, // one output
	0, 0, 0, 0,                      // lock time
};

static void test_channels(void) {
	static const uint8_t local[] = {0xaa, 0xbb};
	uint8_t easy[32], prefix[32], target[32], derived[32], hash[32], zero[32] = {0}, long_extranonce[33] = {0};
	uint8_t extranonce[8] = {1, 2, 3, 4, 5, 6, 7, 8}, tip[32] = {1}, coinbase[512];
	struct Sv2FfiExtranonceAllocator *a;
	struct Sv2FfiExtendedChannel *ch;
	Sv2FfiChannelOpen o;
	Sv2FfiPrebuiltJob job;
	Sv2FfiSubmitSharesExtended share;
	Sv2FfiShareAccounting acc;
	Sv2FfiBytes code;
	uint32_t job_id = 0, coinbase_len = 99;
	size_t block_len = sizeof(cb_prefix) + 4 + sizeof(extranonce) + sizeof(cb_suffix);
	int32_t status = 99, r = 0;

	memset(easy, 0xff, sizeof(easy));
	a = sv2_ffi_extranonce_allocator_new(local, sizeof(local), 12, 1024);
	CHECK(a != NULL);
	if (!a) return;
	CHECK_EQ(sv2_ffi_extranonce_allocator_rollable_size(a), 8);
	CHECK(sv2_ffi_extranonce_allocator_new(local, sizeof(local), 12, 0) == NULL);

	memset(&o, 0, sizeof(o));
	o.channel_id = 7;
	o.user_identity = bytes("worker", 6);
	o.nominal_hash_rate = 1.0e6f;
	o.max_target = easy;
	o.min_extranonce_size = 8;
	o.share_batch_size = 1;
	o.expected_shares_per_minute = 8.0f;
	o.max_past_jobs = 4;
	// a share rate that gives no target is refused at open
	o.expected_shares_per_minute = 0.0f;
	CHECK(sv2_ffi_extended_channel_new(a, &o, &status) == NULL);
	CHECK_EQ(status, SV2_FFI_ERR_CH_NOMINAL_HASHRATE);
	o.expected_shares_per_minute = 8.0f;
	ch = sv2_ffi_extended_channel_new(a, &o, &status);
	CHECK(ch != NULL);
	CHECK_EQ(status, SV2_FFI_OK);
	if (!ch) {
		sv2_ffi_extranonce_allocator_free(a);
		return;
	}
	CHECK_EQ(sv2_ffi_extended_channel_extranonce_prefix(ch, prefix, sizeof(prefix)), 4);
	CHECK(memcmp(prefix, local, sizeof(local)) == 0);
	CHECK_EQ(sv2_ffi_extended_channel_extranonce_prefix(ch, prefix, 2), SV2_FFI_ERR_OVERFLOW);
	// the target the crate derived from the hashrate, which the open's
	// Success carries
	CHECK_EQ(sv2_ffi_extended_channel_target(ch, derived), SV2_FFI_OK);
	CHECK(memcmp(derived, zero, 32) != 0 && memcmp(derived, easy, 32) != 0);
	CHECK_EQ(sv2_ffi_extended_channel_target(ch, NULL), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_extended_channel_target(NULL, derived), SV2_FFI_ERR_INVALID);
	// UpdateChannel: a thousand times the hashrate gives a target of its
	// own, the one the SetTarget after it carries
	CHECK_EQ(sv2_ffi_extended_channel_update(ch, 1.0e9f, easy), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_extended_channel_target(ch, target), SV2_FFI_OK);
	CHECK(memcmp(target, derived, 32) != 0 && memcmp(target, zero, 32) != 0);
	CHECK_EQ(sv2_ffi_extended_channel_update(ch, 1.0e9f, NULL), SV2_FFI_ERR_INVALID);
	// until a SetTarget of the server's own
	CHECK_EQ(sv2_ffi_extended_channel_set_target(ch, easy), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_extended_channel_target(ch, target), SV2_FFI_OK);
	CHECK(memcmp(target, easy, 32) == 0);
	CHECK_EQ(sv2_ffi_extended_channel_set_target(ch, zero), SV2_FFI_ERR_CH_TARGET);

	// a future job, activated by SetNewPrevHash
	memset(&job, 0, sizeof(job));
	job.version = 0x20000000;
	job.coinbase_tx_prefix = bytes(cb_prefix, sizeof(cb_prefix));
	job.coinbase_tx_suffix = bytes(cb_suffix, sizeof(cb_suffix));
	job.merkle_path = bytes(NULL, 0);
	CHECK_EQ(sv2_ffi_extended_channel_prebuilt_job(ch, &job, &job_id), SV2_FFI_OK);
	CHECK(job_id != 0);
	CHECK_EQ(sv2_ffi_extended_channel_job_target(ch, job_id, target), SV2_FFI_ERR_CH_JOB_ID);
	CHECK_EQ(sv2_ffi_extended_channel_activate_job(ch, job_id + 1, zero, 0x1d00ffff, 1700000000), SV2_FFI_ERR_CH_JOB_ID);
	CHECK_EQ(sv2_ffi_extended_channel_activate_job(ch, job_id, zero, 0x1d00ffff, 1700000000), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_extended_channel_job_target(ch, job_id, target), SV2_FFI_OK);
	CHECK(memcmp(target, easy, 32) == 0);

	// no buffer for the hash: refused before the channel sees the share,
	// which is then accepted as new
	memset(&share, 0, sizeof(share));
	share.channel_id = 7;
	share.sequence_number = 1;
	share.job_id = job_id;
	share.nonce = 42;
	share.ntime = 1700000001;
	share.version = 0x20000000;
	share.extranonce = bytes(extranonce, sizeof(extranonce));
	// every return sets *coinbase_len, the refusals before the crate too
	coinbase_len = 99;
	CHECK_EQ(sv2_ffi_extended_channel_validate_share(ch, &share, NULL, coinbase, sizeof(coinbase), &coinbase_len),
	         SV2_FFI_ERR_INVALID);
	CHECK_EQ(coinbase_len, 0);
	// the all-ones target takes any hash, once
	CHECK_EQ(sv2_ffi_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_FFI_SHARE_VALID);
	CHECK(memcmp(hash, zero, 32) != 0);
	CHECK_EQ(sv2_ffi_extended_channel_share_accounting(ch, &acc), SV2_FFI_OK);
	CHECK(acc.should_acknowledge);
	CHECK_EQ(acc.last_share_sequence_number, 1);
	CHECK_EQ(acc.last_batch_accepted, 1);
	CHECK_EQ(acc.share_batch_size, 1);
	CHECK_EQ(acc.shares_accepted, 1);
	CHECK_EQ(acc.shares_rejected, 0);
	CHECK_EQ(acc.blocks_found, 0);
	CHECK(acc.share_work_sum > 0);

	status = sv2_ffi_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL);
	CHECK_EQ(status, SV2_FFI_ERR_SHARE_DUPLICATE);
	code = sv2_ffi_channel_error_code(status);
	CHECK(str_eq(code, "duplicate-share"));
	share.job_id = job_id + 1;
	CHECK_EQ(sv2_ffi_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_FFI_ERR_SHARE_JOB_ID);
	share.job_id = job_id;
	share.nonce = 43;
	share.extranonce = bytes(extranonce, 4);
	CHECK_EQ(sv2_ffi_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_FFI_ERR_SHARE_EXTRANONCE_SIZE);
	// longer than any extranonce can be: the same verdict
	share.extranonce = bytes(long_extranonce, sizeof(long_extranonce));
	coinbase_len = 99;
	CHECK_EQ(sv2_ffi_extended_channel_validate_share(ch, &share, hash, coinbase, sizeof(coinbase), &coinbase_len),
	         SV2_FFI_ERR_SHARE_EXTRANONCE_SIZE);
	CHECK_EQ(coinbase_len, 0);
	CHECK_EQ(sv2_ffi_channel_error_code(SV2_FFI_ERR_INTERNAL).len, 0);
	CHECK_EQ(sv2_ffi_extended_channel_share_accounting(ch, &acc), SV2_FFI_OK);
	CHECK_EQ(acc.shares_accepted, 1);
	// the duplicate, the unknown job and the short extranonce; the one over
	// 32 bytes never reached the crate
	CHECK_EQ(acc.shares_rejected, 3);
	CHECK_EQ(sv2_ffi_extended_channel_share_accounting(ch, NULL), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_extended_channel_share_accounting(NULL, &acc), SV2_FFI_ERR_INVALID);

	// a block, under a tip whose nbits about one hash in two meets
	CHECK_EQ(sv2_ffi_extended_channel_prebuilt_job(ch, &job, &job_id), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_extended_channel_activate_job(ch, job_id, tip, 0x207fffff, 1700000100), SV2_FFI_OK);
	share.job_id = job_id;
	share.ntime = 1700000101;
	share.extranonce = bytes(extranonce, sizeof(extranonce));
	// with a coinbase buffer too short: the length says so, the buffer is
	// left alone
	memset(coinbase, 0xee, sizeof(coinbase));
	for (share.nonce = 100; share.nonce < 200; share.nonce++) {
		r = sv2_ffi_extended_channel_validate_share(ch, &share, hash, coinbase, 16, &coinbase_len);
		if (r == SV2_FFI_SHARE_BLOCK) break;
		CHECK_EQ(r, SV2_FFI_SHARE_VALID);
		CHECK_EQ(coinbase_len, 0);
	}
	CHECK_EQ(r, SV2_FFI_SHARE_BLOCK);
	CHECK_EQ(coinbase_len, block_len);
	CHECK(coinbase[0] == 0xee && coinbase[15] == 0xee);
	// with one that fits: the job's bytes around the channel's prefix and
	// the miner's extranonce
	for (share.nonce++; share.nonce < 300; share.nonce++) {
		r = sv2_ffi_extended_channel_validate_share(ch, &share, hash, coinbase, sizeof(coinbase), &coinbase_len);
		if (r == SV2_FFI_SHARE_BLOCK) break;
	}
	CHECK_EQ(r, SV2_FFI_SHARE_BLOCK);
	CHECK_EQ(coinbase_len, block_len);
	CHECK(memcmp(coinbase, cb_prefix, sizeof(cb_prefix)) == 0);
	CHECK(memcmp(coinbase + sizeof(cb_prefix), prefix, 4) == 0);
	CHECK(memcmp(coinbase + sizeof(cb_prefix) + 4, extranonce, sizeof(extranonce)) == 0);
	CHECK(memcmp(coinbase + sizeof(cb_prefix) + 4 + sizeof(extranonce), cb_suffix, sizeof(cb_suffix)) == 0);
	CHECK_EQ(sv2_ffi_extended_channel_share_accounting(ch, &acc), SV2_FFI_OK);
	CHECK_EQ(acc.blocks_found, 2);

	sv2_ffi_extended_channel_free(ch);
	sv2_ffi_extended_channel_free(NULL);
	sv2_ffi_extranonce_allocator_free(a);
	sv2_ffi_extranonce_allocator_free(NULL);
}

static void test_standard_channel(void) {
	static const uint8_t local[] = {0xcc};
	uint8_t easy[32], prefix[32], target[32], derived[32], root[32], hash[32], zero[32] = {0}, tip[32] = {2};
	uint8_t coinbase[512];
	struct Sv2FfiExtranonceAllocator *a;
	struct Sv2FfiStandardChannel *ch;
	Sv2FfiChannelOpen o;
	Sv2FfiPrebuiltJob job;
	Sv2FfiSubmitSharesStandard share;
	Sv2FfiShareAccounting acc;
	uint32_t job_id = 0, old_job, coinbase_len = 99;
	int32_t status = 99, r = 0, prefix_len, valid = 0, blocks = 0;

	memset(easy, 0xff, sizeof(easy));
	a = sv2_ffi_extranonce_allocator_new(local, sizeof(local), 12, 16);
	CHECK(a != NULL);
	if (!a) return;

	memset(&o, 0, sizeof(o));
	o.channel_id = 9;
	o.nominal_hash_rate = 1.0e6f;
	o.max_target = easy;
	o.share_batch_size = 2;
	o.expected_shares_per_minute = 8.0f;
	// the user identity comes from the miner, UTF-8 or not
	o.user_identity = bytes("\xff\xfe", 2);
	CHECK(sv2_ffi_standard_channel_new(a, &o, &status) == NULL);
	CHECK_EQ(status, SV2_FFI_ERR_INVALID);
	o.user_identity = bytes("worker.std", 10);
	ch = sv2_ffi_standard_channel_new(a, &o, &status);
	CHECK(ch != NULL);
	CHECK_EQ(status, SV2_FFI_OK);
	if (!ch) {
		sv2_ffi_extranonce_allocator_free(a);
		return;
	}
	// the whole extranonce is the channel's
	prefix_len = sv2_ffi_standard_channel_extranonce_prefix(ch, prefix, sizeof(prefix));
	CHECK_EQ(prefix_len, 12);
	CHECK_EQ(prefix[0], 0xcc);
	CHECK_EQ(sv2_ffi_standard_channel_extranonce_prefix(ch, prefix, 11), SV2_FFI_ERR_OVERFLOW);

	CHECK_EQ(sv2_ffi_standard_channel_target(ch, derived), SV2_FFI_OK);
	CHECK(memcmp(derived, zero, 32) != 0 && memcmp(derived, easy, 32) != 0);
	CHECK_EQ(sv2_ffi_standard_channel_target(ch, NULL), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_standard_channel_update(ch, 1.0e9f, easy), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_standard_channel_target(ch, target), SV2_FFI_OK);
	CHECK(memcmp(target, derived, 32) != 0);
	CHECK_EQ(sv2_ffi_standard_channel_update(NULL, 1.0e9f, easy), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_standard_channel_set_target(ch, zero), SV2_FFI_ERR_CH_TARGET);
	CHECK_EQ(sv2_ffi_standard_channel_set_target(ch, easy), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_standard_channel_target(ch, target), SV2_FFI_OK);
	CHECK(memcmp(target, easy, 32) == 0);

	// a future job and its merkle root, which the crate computes from the
	// job's bytes and the channel's extranonce; no buffer for the root is
	// refused before the channel takes the job
	memset(&job, 0, sizeof(job));
	job.version = 0x20000000;
	job.coinbase_tx_prefix = bytes(cb_prefix, sizeof(cb_prefix));
	job.coinbase_tx_suffix = bytes(cb_suffix, sizeof(cb_suffix));
	job.merkle_path = bytes(NULL, 0);
	CHECK_EQ(sv2_ffi_standard_channel_prebuilt_job(ch, &job, &job_id, NULL), SV2_FFI_ERR_INVALID);
	memset(root, 0, sizeof(root));
	CHECK_EQ(sv2_ffi_standard_channel_prebuilt_job(ch, &job, &job_id, root), SV2_FFI_OK);
	CHECK(memcmp(root, zero, 32) != 0);
	CHECK_EQ(sv2_ffi_standard_channel_job_target(ch, job_id, target), SV2_FFI_ERR_CH_JOB_ID);
	CHECK_EQ(sv2_ffi_standard_channel_activate_job(ch, job_id, tip, 0x207fffff, 1700000000), SV2_FFI_OK);
	CHECK_EQ(sv2_ffi_standard_channel_job_target(ch, job_id, target), SV2_FFI_OK);
	CHECK(memcmp(target, easy, 32) == 0);

	// shares until one is a block, which hands back the whole coinbase
	memset(&share, 0, sizeof(share));
	share.channel_id = 9;
	share.job_id = job_id;
	share.ntime = 1700000001;
	share.version = 0x20000000;
	for (share.nonce = 1; share.nonce < 100 && !blocks; share.nonce++) {
		share.sequence_number = share.nonce;
		r = sv2_ffi_standard_channel_validate_share(ch, &share, hash, coinbase, sizeof(coinbase), &coinbase_len);
		if (r == SV2_FFI_SHARE_VALID) {
			valid++;
			CHECK_EQ(coinbase_len, 0);
		} else {
			CHECK_EQ(r, SV2_FFI_SHARE_BLOCK);
			blocks++;
		}
	}
	CHECK_EQ(blocks, 1);
	CHECK_EQ(coinbase_len, sizeof(cb_prefix) + 12 + sizeof(cb_suffix));
	CHECK(memcmp(coinbase, cb_prefix, sizeof(cb_prefix)) == 0);
	CHECK(memcmp(coinbase + sizeof(cb_prefix), prefix, 12) == 0);
	CHECK(memcmp(coinbase + sizeof(cb_prefix) + 12, cb_suffix, sizeof(cb_suffix)) == 0);
	CHECK_EQ(sv2_ffi_standard_channel_share_accounting(ch, &acc), SV2_FFI_OK);
	CHECK_EQ(acc.shares_accepted, valid + 1);
	CHECK_EQ(acc.blocks_found, 1);
	CHECK_EQ(acc.share_batch_size, 2);
	CHECK_EQ(acc.shares_rejected, 0);

	// the same share again, then one on a job the next tip made stale
	share.nonce--;
	CHECK_EQ(sv2_ffi_standard_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_FFI_ERR_SHARE_DUPLICATE);
	old_job = job_id;
	CHECK_EQ(sv2_ffi_standard_channel_prebuilt_job(ch, &job, &job_id, root), SV2_FFI_OK);
	tip[0] = 3;
	CHECK_EQ(sv2_ffi_standard_channel_activate_job(ch, job_id, tip, 0x207fffff, 1700000200), SV2_FFI_OK);
	share.job_id = old_job;
	share.nonce = 1000;
	CHECK_EQ(sv2_ffi_standard_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_FFI_ERR_SHARE_STALE);
	CHECK_EQ(sv2_ffi_standard_channel_validate_share(ch, &share, NULL, NULL, 0, NULL), SV2_FFI_ERR_INVALID);
	CHECK_EQ(sv2_ffi_standard_channel_share_accounting(ch, &acc), SV2_FFI_OK);
	CHECK_EQ(acc.shares_rejected, 2);
	CHECK_EQ(sv2_ffi_standard_channel_share_accounting(ch, NULL), SV2_FFI_ERR_INVALID);

	sv2_ffi_standard_channel_free(ch);
	sv2_ffi_standard_channel_free(NULL);
	sv2_ffi_extranonce_allocator_free(a);
}

int main(void) {
	test_keys();
	test_handshake();
	test_transport_and_messages();
	test_channels();
	test_standard_channel();
	if (failures) {
		fprintf(stderr, "capi_test: %d check(s) failed\n", failures);
		return 1;
	}
	printf("capi_test: all checks passed\n");
	return 0;
}
