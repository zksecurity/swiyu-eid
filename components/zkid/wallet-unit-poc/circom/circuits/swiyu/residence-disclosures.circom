pragma circom 2.2.3;

include "canton-disclosure.circom";

/// Common strict envelope for the two residence SD-JWT disclosures.
/// The profile fixes salts to the RFC 9901 recommendation of 128 random bits,
/// represented as 22 unpadded base64url characters.  It also fixes compact
/// JSON spelling so semantically equivalent spellings do not expand the
/// relation or create multiple accepted encodings.
template SwiyuResidenceDisclosureEnvelope() {
    var ENCODED_MAX = 128;
    var DECODED_MAX = 96;
    var HASH_TAIL = 120;

    signal input encodedPadded[ENCODED_MAX];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal output decoded[DECODED_MAX];
    signal output digestBytes[32];
    signal output saltChars[22];

    component encLenBits = Num2Bits(7); encLenBits.in <== encodedLength;
    component encMin = GreaterEqThan(7); encMin.in[0] <== encodedLength; encMin.in[1] <== 56; encMin.out === 1;
    component encMax = LessEqThan(7); encMax.in[0] <== encodedLength; encMax.in[1] <== 119; encMax.out === 1;
    saltLength === 22;

    component lengthRelation = CantonBase64UrlDecodedLength(ENCODED_MAX, DECODED_MAX);
    lengthRelation.encodedLength <== encodedLength;
    lengthRelation.decodedLength <== decodedLength;
    component canonicalTail = CantonAssertBase64UrlCanonicalTail(ENCODED_MAX, DECODED_MAX);
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
        byteBits[i] = Num2Bits(8); byteBits[i].in <== encodedPadded[i];
        beforeLength[i] = GreaterThan(7); beforeLength[i].in[0] <== encodedLength; beforeLength[i].in[1] <== i;
        atLength[i] = IsEqual(); atLength[i].in[0] <== encodedLength; atLength[i].in[1] <== i;
        strictChars[i] = CantonAssertBase64UrlCharStrict();
        strictChars[i].char <== encodedPadded[i];
        strictChars[i].enabled <== beforeLength[i].out;
        atLength[i].out * (encodedPadded[i] - 128) === 0;
        beforeTail[i] = LessThan(8); beforeTail[i].in[0] <== i; beforeTail[i].in[1] <== HASH_TAIL;
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
    for (var i = 0; i < DECODED_MAX; i++) decoded[i] <== decodedOne[0][i];

    decoded[0] === 91;
    decoded[1] === 34;
    component saltChar[22];
    for (var i = 0; i < 22; i++) {
        saltChar[i] = CantonAssertBase64UrlCharStrict();
        saltChar[i].char <== decoded[2 + i];
        saltChar[i].enabled <== 1;
        saltChars[i] <== decoded[2 + i];
    }
    // A 16-byte value has two residual data bits in its 22nd unpadded base64url
    // character. The four unused low bits must be zero, so the final character
    // is exactly one of A/Q/g/w. Character-class checks alone are insufficient.
    component canonicalSaltTail[4];
    var CANONICAL_LAST[4] = [65, 81, 103, 119];
    signal canonicalSaltTailSum[5];
    canonicalSaltTailSum[0] <== 0;
    for (var i = 0; i < 4; i++) {
        canonicalSaltTail[i] = IsEqual();
        canonicalSaltTail[i].in[0] <== decoded[23];
        canonicalSaltTail[i].in[1] <== CANONICAL_LAST[i];
        canonicalSaltTailSum[i + 1] <== canonicalSaltTailSum[i] + canonicalSaltTail[i].out;
    }
    canonicalSaltTailSum[4] === 1;

    signal digestBits[256] <== Sha256Bytes(ENCODED_MAX)(encodedPadded, ENCODED_MAX);
    component toByte[32];
    for (var i = 0; i < 32; i++) {
        toByte[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) toByte[i].in[7 - j] <== digestBits[i * 8 + j];
        digestBytes[i] <== toByte[i].out;
    }
}

/// Convert a strictly validated Gregorian date to the number of elapsed days
/// since 1900-01-01.  The result fits in 17 bits throughout 1900..2199.
template ResidenceDateToDay1900() {
    signal input bytes[10];
    signal output dayIndex;

    component validDate = IsoDate1900To2199();
    validDate.bytes <== bytes;
    signal numeric <== validDate.numeric;

    signal year <-- numeric \ 10000;
    signal monthDay <== numeric - year * 10000;
    signal month <-- monthDay \ 100;
    signal day <== monthDay - month * 100;
    component yearBits = Num2Bits(12); yearBits.in <== year;
    component monthBits = Num2Bits(4); monthBits.in <== month;
    component dayBits = Num2Bits(6); dayBits.in <== day;

    signal completedYear <== year - 1;
    signal q4 <-- completedYear \ 4;
    signal r4 <== completedYear - q4 * 4;
    component q4Bits = Num2Bits(10); q4Bits.in <== q4;
    component r4Bits = Num2Bits(2); r4Bits.in <== r4;
    signal q100 <-- completedYear \ 100;
    signal r100 <== completedYear - q100 * 100;
    component q100Bits = Num2Bits(5); q100Bits.in <== q100;
    component r100Bits = Num2Bits(7); r100Bits.in <== r100;
    component r100Bound = LessThan(7); r100Bound.in[0] <== r100; r100Bound.in[1] <== 100; r100Bound.out === 1;
    signal q400 <-- completedYear \ 400;
    signal r400 <== completedYear - q400 * 400;
    component q400Bits = Num2Bits(3); q400Bits.in <== q400;
    component r400Bits = Num2Bits(9); r400Bits.in <== r400;
    component r400Bound = LessThan(9); r400Bound.in[0] <== r400; r400Bound.in[1] <== 400; r400Bound.out === 1;

    signal leapDaysBeforeYear <== (q4 - 474) - (q100 - 18) + (q400 - 4);
    component monthEq[12];
    for (var i = 0; i < 12; i++) {
        monthEq[i] = IsEqual(); monthEq[i].in[0] <== month; monthEq[i].in[1] <== i + 1;
    }
    // Circom signals cannot be reassigned in a loop; form explicit linear sums.
    signal monthOffset <== monthEq[1].out * 31 + monthEq[2].out * 59 + monthEq[3].out * 90
        + monthEq[4].out * 120 + monthEq[5].out * 151 + monthEq[6].out * 181
        + monthEq[7].out * 212 + monthEq[8].out * 243 + monthEq[9].out * 273
        + monthEq[10].out * 304 + monthEq[11].out * 334;
    signal monthAfterFebruary <== monthEq[2].out + monthEq[3].out + monthEq[4].out
        + monthEq[5].out + monthEq[6].out + monthEq[7].out + monthEq[8].out
        + monthEq[9].out + monthEq[10].out + monthEq[11].out;
    signal yearQ4 <-- year \ 4;
    signal yearR4 <== year - yearQ4 * 4;
    component yearQ4Bits = Num2Bits(10); yearQ4Bits.in <== yearQ4;
    component yearR4Bits = Num2Bits(2); yearR4Bits.in <== yearR4;
    component r4Zero = IsZero(); r4Zero.in <== yearR4;
    component is1900 = IsEqual(); is1900.in[0] <== year; is1900.in[1] <== 1900;
    component is2100 = IsEqual(); is2100.in[0] <== year; is2100.in[1] <== 2100;
    signal leapThisYear <== r4Zero.out * (1 - is1900.out - is2100.out);

    dayIndex <== (year - 1900) * 365 + leapDaysBeforeYear + monthOffset
        + leapThisYear * monthAfterFebruary + day - 1;
    component indexBits = Num2Bits(17); indexBits.in <== dayIndex;
}

/// Exact [salt,"residence_municipality_bfs",<1..6999>] disclosure.
template SwiyuResidenceMunicipalityDisclosure() {
    var NAME_LEN = 26;
    signal input encodedPadded[128];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal input digitLength;
    signal output municipalityBfs;
    signal output digestBytes[32];
    signal output saltChars[22];

    component envelope = SwiyuResidenceDisclosureEnvelope();
    envelope.encodedPadded <== encodedPadded;
    envelope.encodedLength <== encodedLength;
    envelope.decodedLength <== decodedLength;
    envelope.saltLength <== saltLength;
    digestBytes <== envelope.digestBytes;
    saltChars <== envelope.saltChars;

    component digitLenBits = Num2Bits(3); digitLenBits.in <== digitLength;
    component digitMin = GreaterEqThan(3); digitMin.in[0] <== digitLength; digitMin.in[1] <== 1; digitMin.out === 1;
    component digitMax = LessEqThan(3); digitMax.in[0] <== digitLength; digitMax.in[1] <== 4; digitMax.out === 1;
    decodedLength === saltLength + 34 + digitLength;

    var NAME[NAME_LEN] = [114,101,115,105,100,101,110,99,101,95,109,117,110,105,99,105,112,97,108,105,116,121,95,98,102,115];
    var suffixStart = 24;
    envelope.decoded[suffixStart] === 34;
    envelope.decoded[suffixStart + 1] === 44;
    envelope.decoded[suffixStart + 2] === 34;
    for (var i = 0; i < NAME_LEN; i++) envelope.decoded[suffixStart + 3 + i] === NAME[i];
    envelope.decoded[suffixStart + 29] === 34;
    envelope.decoded[suffixStart + 30] === 44;

    component active[4];
    component lower[4];
    component upper[4];
    signal digits[4];
    signal accumulator[5];
    accumulator[0] <== 0;
    for (var i = 0; i < 4; i++) {
        active[i] = LessThan(3); active[i].in[0] <== i; active[i].in[1] <== digitLength;
        lower[i] = GreaterEqThan(8); lower[i].in[0] <== envelope.decoded[suffixStart + 31 + i]; lower[i].in[1] <== 48;
        upper[i] = LessEqThan(8); upper[i].in[0] <== envelope.decoded[suffixStart + 31 + i]; upper[i].in[1] <== 57;
        active[i].out * (1 - lower[i].out) === 0;
        active[i].out * (1 - upper[i].out) === 0;
        digits[i] <== envelope.decoded[suffixStart + 31 + i] - 48;
        accumulator[i + 1] <== accumulator[i] + active[i].out * (accumulator[i] * 9 + digits[i]);
    }
    component leadingZero = IsEqual(); leadingZero.in[0] <== envelope.decoded[suffixStart + 31]; leadingZero.in[1] <== 48; leadingZero.out === 0;
    signal arrayClose <== SelectArrayValue(96)(envelope.decoded, suffixStart + 31 + digitLength, 1);
    arrayClose === 93;
    municipalityBfs <== accumulator[4];
    component municipalityBits = Num2Bits(13); municipalityBits.in <== municipalityBfs;
    component municipalityMax = LessEqThan(13); municipalityMax.in[0] <== municipalityBfs; municipalityMax.in[1] <== 6999; municipalityMax.out === 1;
}

/// Exact [salt,"residence_since","YYYY-MM-DD"] disclosure.
template SwiyuResidenceSinceDisclosure() {
    var NAME_LEN = 15;
    signal input encodedPadded[128];
    signal input encodedLength;
    signal input decodedLength;
    signal input saltLength;
    signal output residenceSinceDay1900;
    signal output digestBytes[32];
    signal output saltChars[22];

    component envelope = SwiyuResidenceDisclosureEnvelope();
    envelope.encodedPadded <== encodedPadded;
    envelope.encodedLength <== encodedLength;
    envelope.decodedLength <== decodedLength;
    envelope.saltLength <== saltLength;
    digestBytes <== envelope.digestBytes;
    saltChars <== envelope.saltChars;
    decodedLength === saltLength + 35;

    var NAME[NAME_LEN] = [114,101,115,105,100,101,110,99,101,95,115,105,110,99,101];
    var suffixStart = 24;
    envelope.decoded[suffixStart] === 34;
    envelope.decoded[suffixStart + 1] === 44;
    envelope.decoded[suffixStart + 2] === 34;
    for (var i = 0; i < NAME_LEN; i++) envelope.decoded[suffixStart + 3 + i] === NAME[i];
    envelope.decoded[suffixStart + 18] === 34;
    envelope.decoded[suffixStart + 19] === 44;
    envelope.decoded[suffixStart + 20] === 34;
    signal dateBytes[10];
    for (var i = 0; i < 10; i++) dateBytes[i] <== envelope.decoded[suffixStart + 21 + i];
    envelope.decoded[suffixStart + 31] === 34;
    envelope.decoded[suffixStart + 32] === 93;
    component ordinal = ResidenceDateToDay1900(); ordinal.bytes <== dateBytes;
    residenceSinceDay1900 <== ordinal.dayIndex;
}
