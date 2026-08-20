pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

/// @title FindRealMessageLength
/// @notice Finds the length of the real message in a padded array by locating the first occurrence of 128
/// @dev This template is specifically designed for Base64 encoded strings followed by SHA-256 padding.
///      It works because:
///      1. Base64 uses characters with ASCII values < 128
///      2. SHA-256 padding starts with 128 (10000000 in binary)
///      3. The first 128 encountered marks the end of the Base64 string and start of padding
/// @input in[maxLength] The padded message array
/// @input maxLength The maximum possible length of the padded message
/// @output realLength The length of the real message (before padding)
template FindRealMessageLength(maxLength) {
    signal input in[maxLength];
    signal output realLength;

    // Signal to track if we've found 128
    signal found[maxLength + 1];
    found[0] <== 0;

    // Signal to accumulate the length
    signal lengthAcc[maxLength + 1];
    lengthAcc[0] <== 0;

    signal is128[maxLength];

    // Iterate through the array
    for (var i = 0; i < maxLength; i++) {
        // Check if current element is 128
        is128[i] <== IsEqual()([in[i], 128]);

        // Update found signal
        found[i + 1] <== found[i] + is128[i] - found[i] * is128[i];

        // If 128 not found yet, increment length
        lengthAcc[i + 1] <== lengthAcc[i] + 1 - found[i + 1];
    }

    // The final accumulated length is our real message length
    realLength <== lengthAcc[maxLength];

    // Constraint to ensure 128 was really found
    found[maxLength] === 1;
}

/// @title CountCharOccurrences
/// @notice Counts the number of occurrences of a specified character in an array
/// @dev This template iterates through the input array and counts how many times the specified character appears.
/// @input in[maxLength] The input array in which to count occurrences of the character
/// @input char The character to count within the input array
/// @output count The number of times the specified character appears in the input array
template CountCharOccurrences(maxLength) {
    signal input in[maxLength];
    signal input char;
    signal output count;

    signal match[maxLength];
    signal counter[maxLength];

    match[0] <== IsEqual()([in[0], char]);
    counter[0] <== match[0];

    for (var i = 1; i < maxLength; i++) {
        match[i] <== IsEqual()([in[i], char]);
        counter[i] <== counter[i-1] + match[i];
    }

    count <== counter[maxLength-1];
}

/// Count a character only in the declared prefix.  This is required for
/// SHA-256-padded messages: the final bit-length word is authenticated padding,
/// not compact-JWS syntax, and may itself contain the byte being counted.
template CountCharOccurrencesBefore(maxLength) {
    signal input in[maxLength];
    signal input char;
    signal input length;
    signal output count;

    var LEN_BITS = log2Ceil(maxLength + 1);
    component lengthBits = Num2Bits(LEN_BITS);
    lengthBits.in <== length;

    component before[maxLength];
    component equal[maxLength];
    signal match[maxLength];
    signal counter[maxLength + 1];
    counter[0] <== 0;

    for (var i = 0; i < maxLength; i++) {
        before[i] = GreaterThan(LEN_BITS);
        before[i].in[0] <== length;
        before[i].in[1] <== i;
        equal[i] = IsEqual();
        equal[i].in[0] <== in[i];
        equal[i].in[1] <== char;
        match[i] <== before[i].out * equal[i].out;
        counter[i + 1] <== counter[i] + match[i];
    }

    count <== counter[maxLength];
}
