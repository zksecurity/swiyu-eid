pragma circom 2.2.3;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/hash.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/base64.circom";
include "../ecdsa/ecdsa.circom";
include "utils.circom";

template ES256(
    maxMessageLength
) {
    signal input message[maxMessageLength];
    signal input messageLength; 

    signal input sig_r;
    signal input sig_s_inverse;
    signal input pubKeyX;
    signal input pubKeyY;

    // Expose the already-computed digest so enclosing, versioned profiles can
    // bind auxiliary issuer data to this exact protected-header/payload JWS
    // without hashing the 896-byte signing input a second time.
    signal output sha[256];

    // Include the exact upper bound. For power-of-two buffers (for example the
    // 128-byte auxiliary attestation), log2Ceil(maxMessageLength) cannot encode
    // maxMessageLength itself.
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength + 1));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Calculate SHA256 hash of the message
    sha <== Sha256Bytes(maxMessageLength)(message, messageLength);

    // Reduce message hash modulo scalar field order q
    component message_hash_mod_q = HashModScalarField();
    message_hash_mod_q.hash <== sha;

    // Verify the signature
    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== message_hash_mod_q.out;
    ecdsa.pubKeyX <== pubKeyX;
    ecdsa.pubKeyY <== pubKeyY;
}
