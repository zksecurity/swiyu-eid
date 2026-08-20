pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/hash.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/base64.circom";
include "bytes.circom";
include "array.circom";

template HeaderPayloadExtractor(
    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message

    var maxHeaderLength = (maxB64HeaderLength * 3) \ 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    signal output header[maxHeaderLength];
    signal output payload[maxPayloadLength];

    // Assert message length fits in ceil(log2(maxMessageLength))
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Find the signed prefix before inspecting compact-JWS syntax.  SHA-256's
    // marker and length word are not part of the header.payload string.
    signal realMessageLength <== FindRealMessageLength(maxMessageLength)(message);

    component periodBeforeEnd = LessThan(log2Ceil(maxMessageLength + 1));
    periodBeforeEnd.in[0] <== periodIndex;
    periodBeforeEnd.in[1] <== realMessageLength;
    periodBeforeEnd.out === 1;

    // Assert that period exists at periodIndex
    signal period <== ItemAtIndex(maxMessageLength)(message, periodIndex);
    period === 46;

    // Assert that period is unique inside the signed prefix.  In particular,
    // do not count a 0x2e byte in SHA-256's final bit-length word.
    signal periodCount <== CountCharOccurrencesBefore(maxMessageLength)(message, 46, realMessageLength);
    periodCount === 1;

    // Calculate the length of the Base64 encoded header and payload
    signal b64HeaderLength <== periodIndex;
    signal b64PayloadLength <== realMessageLength - b64HeaderLength - 1;

    // Extract the Base64 encoded header and payload from the message
    signal b64Header[maxB64HeaderLength] <== SelectSubArrayBase64(maxMessageLength, maxB64HeaderLength)(message, 0, b64HeaderLength);
    signal b64Payload[maxB64PayloadLength] <== SelectSubArrayBase64(maxMessageLength, maxB64PayloadLength)(message, b64HeaderLength + 1, b64PayloadLength);

    // Decode the Base64 encoded header and payload
    header <== Base64Decode(maxHeaderLength)(b64Header);
    payload <== Base64Decode(maxPayloadLength)(b64Payload);
}


// PayloadExtractor is used to extract the payload from the message
template PayloadExtractor(
    maxMessageLength,
    maxB64PayloadLength
) {
    signal input message[maxMessageLength]; // JWT message (header + payload)
    signal input messageLength; // Length of the message signed in the JWT
    signal input periodIndex; // Index of the period in the JWT message

    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;

    signal output payload[maxPayloadLength];

    // Assert message length fits in ceil(log2(maxMessageLength))
    component n2bMessageLength = Num2Bits(log2Ceil(maxMessageLength));
    n2bMessageLength.in <== messageLength;

    // Assert message data after messageLength are zeros
    AssertZeroPadding(maxMessageLength)(message, messageLength);

    // Find the signed prefix before inspecting compact-JWS syntax.
    signal realMessageLength <== FindRealMessageLength(maxMessageLength)(message);

    component periodBeforeEnd = LessThan(log2Ceil(maxMessageLength + 1));
    periodBeforeEnd.in[0] <== periodIndex;
    periodBeforeEnd.in[1] <== realMessageLength;
    periodBeforeEnd.out === 1;

    // Assert that period exists at periodIndex
    signal period <== ItemAtIndex(maxMessageLength)(message, periodIndex);
    period === 46;

    // Assert that period is unique inside the signed prefix.
    signal periodCount <== CountCharOccurrencesBefore(maxMessageLength)(message, 46, realMessageLength);
    periodCount === 1;

    // Calculate the length of the Base64 encoded payload
    signal b64PayloadLength <== realMessageLength - periodIndex - 1;

    // Extract the Base64 encoded payload from the message
    signal b64Payload[maxB64PayloadLength] <== SelectSubArrayBase64(maxMessageLength, maxB64PayloadLength)(message, periodIndex + 1, b64PayloadLength);

    // Decode the Base64 encoded payload
    payload <== Base64Decode(maxPayloadLength)(b64Payload);
}
