pragma circom 2.2.3;

include "residence-disclosures.circom";

/// Experimental A/B representation for the residence predicate.
///
/// It authenticates exactly one RFC 9901 object-valued disclosure:
/// [salt,"residence",{"municipality_bfs":261,"since":"2023-01-01"}]
///
/// This deliberately changes selective-disclosure granularity: municipality
/// and date can no longer be released independently. The original
/// two-disclosure relation remains separate and unchanged as a controlled A/B.
template SwiyuResidenceCombinedDisclosure() {
    signal input encodedPadded[128];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal input municipalityDigitLength;
    signal output municipalityBfs;
    signal output residenceSinceDay1900;
    signal output digestBytes[32];

    component envelope = SwiyuResidenceDisclosureEnvelope();
    envelope.encodedPadded <== encodedPadded;
    envelope.encodedLength <== encodedLength;
    envelope.decodedLength <== decodedLength;
    envelope.saltLength <== saltLength;
    digestBytes <== envelope.digestBytes;

    component digitLenBits = Num2Bits(3);
    digitLenBits.in <== municipalityDigitLength;
    component digitMin = GreaterEqThan(3);
    digitMin.in[0] <== municipalityDigitLength;
    digitMin.in[1] <== 1;
    digitMin.out === 1;
    component digitMax = LessEqThan(3);
    digitMax.in[0] <== municipalityDigitLength;
    digitMax.in[1] <== 4;
    digitMax.out === 1;

    // Exact active decoded length: 59 fixed bytes, the 22 salt characters,
    // and the 1..4 municipality digits (82..85 bytes overall).
    decodedLength === saltLength + 59 + municipalityDigitLength;

    // Bytes 0..23 (opening quote plus salt) are fixed by the shared envelope.
    var NAME[9] = [114,101,115,105,100,101,110,99,101]; // residence
    envelope.decoded[24] === 34;
    envelope.decoded[25] === 44;
    envelope.decoded[26] === 34;
    for (var i = 0; i < 9; i++) envelope.decoded[27 + i] === NAME[i];
    envelope.decoded[36] === 34;
    envelope.decoded[37] === 44;
    envelope.decoded[38] === 123;
    envelope.decoded[39] === 34;

    var MUNICIPALITY_KEY[16] = [109,117,110,105,99,105,112,97,108,105,116,121,95,98,102,115];
    for (var i = 0; i < 16; i++) envelope.decoded[40 + i] === MUNICIPALITY_KEY[i];
    envelope.decoded[56] === 34;
    envelope.decoded[57] === 58;

    component active[4];
    component lower[4];
    component upper[4];
    signal digits[4];
    signal accumulator[5];
    accumulator[0] <== 0;
    for (var i = 0; i < 4; i++) {
        active[i] = LessThan(3);
        active[i].in[0] <== i;
        active[i].in[1] <== municipalityDigitLength;
        lower[i] = GreaterEqThan(8);
        lower[i].in[0] <== envelope.decoded[58 + i];
        lower[i].in[1] <== 48;
        upper[i] = LessEqThan(8);
        upper[i].in[0] <== envelope.decoded[58 + i];
        upper[i].in[1] <== 57;
        active[i].out * (1 - lower[i].out) === 0;
        active[i].out * (1 - upper[i].out) === 0;
        digits[i] <== envelope.decoded[58 + i] - 48;
        accumulator[i + 1] <== accumulator[i]
            + active[i].out * (accumulator[i] * 9 + digits[i]);
    }
    component leadingZero = IsEqual();
    leadingZero.in[0] <== envelope.decoded[58];
    leadingZero.in[1] <== 48;
    leadingZero.out === 0;
    municipalityBfs <== accumulator[4];
    component municipalityBits = Num2Bits(13);
    municipalityBits.in <== municipalityBfs;
    component municipalityMax = LessEqThan(13);
    municipalityMax.in[0] <== municipalityBfs;
    municipalityMax.in[1] <== 6999;
    municipalityMax.out === 1;

    // The suffix has only four possible offsets. Reuse four one-hot selectors
    // for all 23 bytes instead of instantiating a 96-way selector per byte.
    // This keeps the exact parser cheap without trusting a prover-supplied
    // dynamic index.
    component digitLengthIs[4];
    signal suffixByte[23];
    for (var digitCase = 0; digitCase < 4; digitCase++) {
        digitLengthIs[digitCase] = IsEqual();
        digitLengthIs[digitCase].in[0] <== municipalityDigitLength;
        digitLengthIs[digitCase].in[1] <== digitCase + 1;
    }
    signal selectedSuffixByte[23][4];
    for (var i = 0; i < 23; i++) {
        for (var digitCase = 0; digitCase < 4; digitCase++) {
            selectedSuffixByte[i][digitCase] <== digitLengthIs[digitCase].out
                * envelope.decoded[59 + digitCase + i];
        }
        suffixByte[i] <== selectedSuffixByte[i][0] + selectedSuffixByte[i][1]
            + selectedSuffixByte[i][2] + selectedSuffixByte[i][3];
    }
    suffixByte[0] === 44;
    suffixByte[1] === 34;
    var SINCE_KEY[5] = [115,105,110,99,101];
    for (var i = 0; i < 5; i++) {
        suffixByte[2 + i] === SINCE_KEY[i];
    }
    suffixByte[7] === 34;
    suffixByte[8] === 58;
    suffixByte[9] === 34;

    signal dateBytes[10];
    for (var i = 0; i < 10; i++) {
        dateBytes[i] <== suffixByte[10 + i];
    }
    suffixByte[20] === 34;
    suffixByte[21] === 125;
    suffixByte[22] === 93;

    component ordinal = ResidenceDateToDay1900();
    ordinal.bytes <== dateBytes;
    residenceSinceDay1900 <== ordinal.dayIndex;
}
