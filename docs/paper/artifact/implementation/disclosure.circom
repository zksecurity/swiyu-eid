pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "@zk-email/circuits/lib/sha.circom";
include "../components/claim-decoder.circom";
include "../utils/utils.circom";
include "date.circom";

/// Bind an unpadded base64url length to the decoded byte length.
template Base64UrlDecodedLength(maxEncoded, maxDecoded) {
    signal input encodedLength;
    signal input decodedLength;

    component encBits = Num2Bits(log2Ceil(maxEncoded + 1));
    encBits.in <== encodedLength;
    component decBits = Num2Bits(log2Ceil(maxDecoded + 1));
    decBits.in <== decodedLength;

    signal quotient <-- decodedLength \ 3;
    signal remainder <== decodedLength - quotient * 3;
    component quotientBits = Num2Bits(log2Ceil(maxDecoded / 3 + 2));
    quotientBits.in <== quotient;
    component remainderBits = Num2Bits(2);
    remainderBits.in <== remainder;
    component remainderIsThree = IsEqual();
    remainderIsThree.in[0] <== remainder;
    remainderIsThree.in[1] <== 3;
    remainderIsThree.out === 0;

    component remOne = IsEqual(); remOne.in[0] <== remainder; remOne.in[1] <== 1;
    component remTwo = IsEqual(); remTwo.in[0] <== remainder; remTwo.in[1] <== 2;
    encodedLength === quotient * 4 + remOne.out * 2 + remTwo.out * 3;
}

template AssertBase64UrlCharStrict() {
    signal input char;
    signal input enabled;
    enabled * (1 - enabled) === 0;

    component upperLo = GreaterEqThan(8); upperLo.in[0] <== char; upperLo.in[1] <== 65;
    component upperHi = LessEqThan(8); upperHi.in[0] <== char; upperHi.in[1] <== 90;
    signal upper <== upperLo.out * upperHi.out;
    component lowerLo = GreaterEqThan(8); lowerLo.in[0] <== char; lowerLo.in[1] <== 97;
    component lowerHi = LessEqThan(8); lowerHi.in[0] <== char; lowerHi.in[1] <== 122;
    signal lower <== lowerLo.out * lowerHi.out;
    component digitLo = GreaterEqThan(8); digitLo.in[0] <== char; digitLo.in[1] <== 48;
    component digitHi = LessEqThan(8); digitHi.in[0] <== char; digitHi.in[1] <== 57;
    signal digit <== digitLo.out * digitHi.out;
    component dash = IsEqual(); dash.in[0] <== char; dash.in[1] <== 45;
    component under = IsEqual(); under.in[0] <== char; under.in[1] <== 95;
    signal alpha <== upper + lower;
    signal alphaNum <== alpha + digit;
    signal allowed <== alphaNum + dash.out + under.out;
    enabled * (1 - allowed) === 0;
}

/// Translate one strict base64url character to its six-bit value.
template Base64UrlSextet() {
    signal input char;
    signal output value;

    component strict = AssertBase64UrlCharStrict();
    strict.char <== char;
    strict.enabled <== 1;

    component dash = IsEqual(); dash.in[0] <== char; dash.in[1] <== 45;
    component under = IsEqual(); under.in[0] <== char; under.in[1] <== 95;
    signal standardChar <== char - dash.out * 2 - under.out * 48;
    component lookup = Base64Lookup();
    lookup.in <== standardChar;
    value <== lookup.out;
}

/// A 32-byte value has 43 unpadded base64url characters.  The final sextet
/// carries four data bits, so its two unused low bits must be zero.  Without
/// this check four textual encodings decode to the same digest/coordinate.
template AssertBase64UrlCanonical32() {
    signal input encoded[43];

    component strict[43];
    for (var i = 0; i < 43; i++) {
        strict[i] = AssertBase64UrlCharStrict();
        strict[i].char <== encoded[i];
        strict[i].enabled <== 1;
    }
    component last = Base64UrlSextet();
    last.char <== encoded[42];
    component bits = Num2Bits(6);
    bits.in <== last.value;
    bits.out[0] === 0;
    bits.out[1] === 0;
}

/// Enforce RFC 4648's zero unused-bit rule for a dynamically sized unpadded
/// base64url value whose decoded length is already known.
template AssertBase64UrlCanonicalTail(maxEncoded, maxDecoded) {
    signal input encoded[maxEncoded];
    signal input encodedLength;
    signal input decodedLength;

    component relation = Base64UrlDecodedLength(maxEncoded, maxDecoded);
    relation.encodedLength <== encodedLength;
    relation.decodedLength <== decodedLength;

    component nonEmpty = GreaterEqThan(log2Ceil(maxEncoded + 1));
    nonEmpty.in[0] <== encodedLength;
    nonEmpty.in[1] <== 1;
    nonEmpty.out === 1;

    signal quotient <-- decodedLength \ 3;
    signal remainder <== decodedLength - quotient * 3;
    component quotientBits = Num2Bits(log2Ceil(maxDecoded / 3 + 2));
    quotientBits.in <== quotient;
    component remainderBits = Num2Bits(2);
    remainderBits.in <== remainder;
    component remThree = IsEqual(); remThree.in[0] <== remainder; remThree.in[1] <== 3;
    remThree.out === 0;
    component remOne = IsEqual(); remOne.in[0] <== remainder; remOne.in[1] <== 1;
    component remTwo = IsEqual(); remTwo.in[0] <== remainder; remTwo.in[1] <== 2;

    signal lastChar <== SelectArrayValue(maxEncoded)(encoded, encodedLength - 1, 1);
    component last = Base64UrlSextet();
    last.char <== lastChar;
    component bits = Num2Bits(6);
    bits.in <== last.value;
    remOne.out * bits.out[0] === 0;
    remOne.out * bits.out[1] === 0;
    remOne.out * bits.out[2] === 0;
    remOne.out * bits.out[3] === 0;
    remTwo.out * bits.out[0] === 0;
    remTwo.out * bits.out[1] === 0;
}

/// Validate the exact SHA-256 padding already present in an input buffer.
/// `realLength` excludes padding; `paddedLength` is the whole block-aligned
/// message length supplied to Sha256Bytes.
template AssertSha256Padding(maxLen) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    signal input bytes[maxLen];
    signal input realLength;
    signal input paddedLength;

    component realBits = Num2Bits(LEN_BITS); realBits.in <== realLength;
    component paddedBits = Num2Bits(LEN_BITS); paddedBits.in <== paddedLength;
    component realFits = LessThan(LEN_BITS);
    realFits.in[0] <== realLength;
    realFits.in[1] <== paddedLength;
    realFits.out === 1;

    signal blockCount <-- paddedLength \ 64;
    component blockBits = Num2Bits(log2Ceil(maxLen / 64 + 1));
    blockBits.in <== blockCount;
    paddedLength === blockCount * 64;

    component enoughPadding = GreaterEqThan(LEN_BITS);
    enoughPadding.in[0] <== paddedLength;
    enoughPadding.in[1] <== realLength + 9;
    enoughPadding.out === 1;
    component minimalBlock = LessEqThan(LEN_BITS);
    minimalBlock.in[0] <== paddedLength;
    minimalBlock.in[1] <== realLength + 72;
    minimalBlock.out === 1;

    signal marker <== SelectArrayValue(maxLen)(bytes, realLength, 1);
    marker === 128;

    component afterReal[maxLen];
    component beforeTail[maxLen];
    component beforePadded[maxLen];
    signal middleZero[maxLen];
    signal outsideZero[maxLen];
    for (var i = 0; i < maxLen; i++) {
        afterReal[i] = LessThan(LEN_BITS);
        afterReal[i].in[0] <== realLength;
        afterReal[i].in[1] <== i;
        beforeTail[i] = LessThan(LEN_BITS);
        beforeTail[i].in[0] <== i;
        beforeTail[i].in[1] <== paddedLength - 8;
        middleZero[i] <== afterReal[i].out * beforeTail[i].out;
        middleZero[i] * bytes[i] === 0;

        beforePadded[i] = LessThan(LEN_BITS);
        beforePadded[i].in[0] <== i;
        beforePadded[i].in[1] <== paddedLength;
        outsideZero[i] <== 1 - beforePadded[i].out;
        outsideZero[i] * bytes[i] === 0;
    }

    signal lengthBytes[8];
    for (var i = 0; i < 8; i++) {
        lengthBytes[i] <== SelectArrayValue(maxLen)(bytes, paddedLength - 8 + i, 1);
    }
    component lengthNumber = BytesToNumberBE(8);
    lengthNumber.in <== lengthBytes;
    lengthNumber.out === realLength * 8;
}

/// Proves the exact SD-JWT disclosure tuple
///   [salt, "birthdate", "YYYY-MM-DD"]
/// and exposes only the normalized date plus the SHA-256 digest bytes used for
/// membership in the credential's signed top-level `_sd` array.
template SwiyuBirthdateDisclosure() {
    var ENCODED_MAX = 128;
    var DECODED_MAX = 96;
    var HASH_TAIL = 120;
    var NAME_LEN = 9;

    signal input encodedPadded[ENCODED_MAX];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal output birthdateNumeric;
    signal output digestBytes[32];

    component encLenBits = Num2Bits(7);
    encLenBits.in <== encodedLength;
    component encMin = GreaterEqThan(7); encMin.in[0] <== encodedLength; encMin.in[1] <== 56;
    encMin.out === 1;
    component encMax = LessEqThan(7); encMax.in[0] <== encodedLength; encMax.in[1] <== 119;
    encMax.out === 1;

    component saltLenBits = Num2Bits(6);
    saltLenBits.in <== saltLength;
    component saltMin = GreaterEqThan(6); saltMin.in[0] <== saltLength; saltMin.in[1] <== 16;
    saltMin.out === 1;
    component saltMax = LessEqThan(6); saltMax.in[0] <== saltLength; saltMax.in[1] <== 48;
    saltMax.out === 1;

    component lengthRelation = Base64UrlDecodedLength(ENCODED_MAX, DECODED_MAX);
    lengthRelation.encodedLength <== encodedLength;
    lengthRelation.decodedLength <== decodedLength;
    decodedLength === saltLength + 29;

    component canonicalTail = AssertBase64UrlCanonicalTail(ENCODED_MAX, DECODED_MAX);
    canonicalTail.encoded <== encodedPadded;
    canonicalTail.encodedLength <== encodedLength;
    canonicalTail.decodedLength <== decodedLength;

    component byteBits[ENCODED_MAX];
    component beforeLength[ENCODED_MAX];
    component atLength[ENCODED_MAX];
    component strictChars[ENCODED_MAX];
    component beforeTail[ENCODED_MAX];
    signal afterLength[ENCODED_MAX];
    signal zeroRegion[ENCODED_MAX];
    for (var i = 0; i < ENCODED_MAX; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== encodedPadded[i];
        beforeLength[i] = GreaterThan(7);
        beforeLength[i].in[0] <== encodedLength;
        beforeLength[i].in[1] <== i;
        atLength[i] = IsEqual();
        atLength[i].in[0] <== encodedLength;
        atLength[i].in[1] <== i;
        strictChars[i] = AssertBase64UrlCharStrict();
        strictChars[i].char <== encodedPadded[i];
        strictChars[i].enabled <== beforeLength[i].out;

        // Exact SHA padding: 0x80 immediately follows the disclosure, then
        // zeroes up to the final 64-bit length word at byte 120.
        atLength[i].out * (encodedPadded[i] - 128) === 0;
        beforeTail[i] = LessThan(8);
        beforeTail[i].in[0] <== i;
        beforeTail[i].in[1] <== HASH_TAIL;
        afterLength[i] <== 1 - beforeLength[i].out - atLength[i].out;
        zeroRegion[i] <== afterLength[i] * beforeTail[i].out;
        zeroRegion[i] * encodedPadded[i] === 0;
    }
    encodedPadded[120] === 0;
    encodedPadded[121] === 0;
    encodedPadded[122] === 0;
    encodedPadded[123] === 0;
    component tailLength = BytesToNumberBE(4);
    for (var i = 0; i < 4; i++) tailLength.in[i] <== encodedPadded[124 + i];
    tailLength.out === encodedLength * 8;

    signal flags[1]; flags[0] <== 1;
    signal lengths[1]; lengths[0] <== encodedLength;
    signal claims[1][ENCODED_MAX];
    for (var i = 0; i < ENCODED_MAX; i++) claims[0][i] <== encodedPadded[i];
    signal decodedOne[1][DECODED_MAX] <== ClaimDecoder(1, ENCODED_MAX)(claims, lengths, flags);
    signal decoded[DECODED_MAX];
    for (var i = 0; i < DECODED_MAX; i++) decoded[i] <== decodedOne[0][i];

    decoded[0] === 91;
    decoded[1] === 34;
    component saltActive[48];
    component saltChar[48];
    for (var i = 0; i < 48; i++) {
        saltActive[i] = GreaterThan(6);
        saltActive[i].in[0] <== saltLength;
        saltActive[i].in[1] <== i;
        saltChar[i] = AssertBase64UrlCharStrict();
        saltChar[i].char <== decoded[2 + i];
        saltChar[i].enabled <== saltActive[i].out;
    }

    var NAME[NAME_LEN] = [98,105,114,116,104,100,97,116,101];
    signal nameChar[NAME_LEN];
    signal suffixStart <== 2 + saltLength;
    signal suffix0 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart, 1); suffix0 === 34;
    signal suffix1 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 1, 1); suffix1 === 44;
    signal suffix2 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 2, 1); suffix2 === 34;
    for (var i = 0; i < NAME_LEN; i++) {
        nameChar[i] <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 3 + i, 1);
        nameChar[i] === NAME[i];
    }
    signal suffix12 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 12, 1); suffix12 === 34;
    signal suffix13 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 13, 1); suffix13 === 44;
    signal suffix14 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 14, 1); suffix14 === 34;

    signal dateBytes[10];
    for (var i = 0; i < 10; i++) {
        dateBytes[i] <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 15 + i, 1);
    }
    signal dateClose <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 25, 1); dateClose === 34;
    signal arrayClose <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 26, 1); arrayClose === 93;

    component date = IsoDate1900To2199();
    date.bytes <== dateBytes;
    birthdateNumeric <== date.numeric;

    signal digestBits[256] <== Sha256Bytes(ENCODED_MAX)(encodedPadded, ENCODED_MAX);
    component toByte[32];
    for (var i = 0; i < 32; i++) {
        toByte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) toByte[i].in[7 - j] <== digestBits[i * 8 + j];
        digestBytes[i] <== toByte[i].out;
    }
}

/// Same disclosure relation as SwiyuBirthdateDisclosure, but the authenticated
/// claim name is `birth_date` (EPFL d10 / shared age-25 claim).
template SwiyuBirthDateDisclosure() {
    var ENCODED_MAX = 128;
    var DECODED_MAX = 96;
    var HASH_TAIL = 120;
    var NAME_LEN = 10;

    signal input encodedPadded[ENCODED_MAX];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal output birthdateNumeric;
    signal output digestBytes[32];

    component encLenBits = Num2Bits(7);
    encLenBits.in <== encodedLength;
    component encMin = GreaterEqThan(7); encMin.in[0] <== encodedLength; encMin.in[1] <== 56;
    encMin.out === 1;
    component encMax = LessEqThan(7); encMax.in[0] <== encodedLength; encMax.in[1] <== 119;
    encMax.out === 1;

    component saltLenBits = Num2Bits(6);
    saltLenBits.in <== saltLength;
    component saltMin = GreaterEqThan(6); saltMin.in[0] <== saltLength; saltMin.in[1] <== 16;
    saltMin.out === 1;
    component saltMax = LessEqThan(6); saltMax.in[0] <== saltLength; saltMax.in[1] <== 48;
    saltMax.out === 1;

    component lengthRelation = Base64UrlDecodedLength(ENCODED_MAX, DECODED_MAX);
    lengthRelation.encodedLength <== encodedLength;
    lengthRelation.decodedLength <== decodedLength;
    decodedLength === saltLength + 30;

    component canonicalTail = AssertBase64UrlCanonicalTail(ENCODED_MAX, DECODED_MAX);
    canonicalTail.encoded <== encodedPadded;
    canonicalTail.encodedLength <== encodedLength;
    canonicalTail.decodedLength <== decodedLength;

    component byteBits[ENCODED_MAX];
    component beforeLength[ENCODED_MAX];
    component atLength[ENCODED_MAX];
    component strictChars[ENCODED_MAX];
    component beforeTail[ENCODED_MAX];
    signal afterLength[ENCODED_MAX];
    signal zeroRegion[ENCODED_MAX];
    for (var i = 0; i < ENCODED_MAX; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== encodedPadded[i];
        beforeLength[i] = GreaterThan(7);
        beforeLength[i].in[0] <== encodedLength;
        beforeLength[i].in[1] <== i;
        atLength[i] = IsEqual();
        atLength[i].in[0] <== encodedLength;
        atLength[i].in[1] <== i;
        strictChars[i] = AssertBase64UrlCharStrict();
        strictChars[i].char <== encodedPadded[i];
        strictChars[i].enabled <== beforeLength[i].out;

        atLength[i].out * (encodedPadded[i] - 128) === 0;
        beforeTail[i] = LessThan(8);
        beforeTail[i].in[0] <== i;
        beforeTail[i].in[1] <== HASH_TAIL;
        afterLength[i] <== 1 - beforeLength[i].out - atLength[i].out;
        zeroRegion[i] <== afterLength[i] * beforeTail[i].out;
        zeroRegion[i] * encodedPadded[i] === 0;
    }
    encodedPadded[120] === 0;
    encodedPadded[121] === 0;
    encodedPadded[122] === 0;
    encodedPadded[123] === 0;
    component tailLength = BytesToNumberBE(4);
    for (var i = 0; i < 4; i++) tailLength.in[i] <== encodedPadded[124 + i];
    tailLength.out === encodedLength * 8;

    signal flags[1]; flags[0] <== 1;
    signal lengths[1]; lengths[0] <== encodedLength;
    signal claims[1][ENCODED_MAX];
    for (var i = 0; i < ENCODED_MAX; i++) claims[0][i] <== encodedPadded[i];
    signal decodedOne[1][DECODED_MAX] <== ClaimDecoder(1, ENCODED_MAX)(claims, lengths, flags);
    signal decoded[DECODED_MAX];
    for (var i = 0; i < DECODED_MAX; i++) decoded[i] <== decodedOne[0][i];

    decoded[0] === 91;
    decoded[1] === 34;
    component saltActive[48];
    component saltChar[48];
    for (var i = 0; i < 48; i++) {
        saltActive[i] = GreaterThan(6);
        saltActive[i].in[0] <== saltLength;
        saltActive[i].in[1] <== i;
        saltChar[i] = AssertBase64UrlCharStrict();
        saltChar[i].char <== decoded[2 + i];
        saltChar[i].enabled <== saltActive[i].out;
    }

    var NAME[NAME_LEN] = [98,105,114,116,104,95,100,97,116,101];
    signal nameChar[NAME_LEN];
    signal suffixStart <== 2 + saltLength;
    signal suffix0 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart, 1); suffix0 === 34;
    signal suffix1 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 1, 1); suffix1 === 44;
    signal suffix2 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 2, 1); suffix2 === 34;
    for (var i = 0; i < NAME_LEN; i++) {
        nameChar[i] <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 3 + i, 1);
        nameChar[i] === NAME[i];
    }
    signal suffix13 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 13, 1); suffix13 === 34;
    signal suffix14 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 14, 1); suffix14 === 44;
    signal suffix15 <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 15, 1); suffix15 === 34;

    signal dateBytes[10];
    for (var i = 0; i < 10; i++) {
        dateBytes[i] <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 16 + i, 1);
    }
    signal dateClose <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 26, 1); dateClose === 34;
    signal arrayClose <== SelectArrayValue(DECODED_MAX)(decoded, suffixStart + 27, 1); arrayClose === 93;

    component date = IsoDate1900To2199();
    date.bytes <== dateBytes;
    birthdateNumeric <== date.numeric;

    signal digestBits[256] <== Sha256Bytes(ENCODED_MAX)(encodedPadded, ENCODED_MAX);
    component toByte[32];
    for (var i = 0; i < 32; i++) {
        toByte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) toByte[i].in[7 - j] <== digestBits[i * 8 + j];
        digestBytes[i] <== toByte[i].out;
    }
}
