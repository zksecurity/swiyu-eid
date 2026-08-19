pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";

/// Structural scanner for the compact JSON carried by the swiyu proof profile.
///
/// This is intentionally not a general JSON value decoder.  It provides the
/// security property the profile needs: field selectors below can only start
/// outside strings, at an exact object depth, and duplicate literal keys are
/// rejected.  Quotes preceded by an odd run of backslashes are treated as
/// escaped.  Object and array depths are independently range checked and may
/// never underflow.
template JsonStructure(maxLen) {
    var LEN_BITS = log2Ceil(maxLen + 1);

    signal input json[maxLen];
    signal input jsonLength;

    signal output active[maxLen];
    signal output inStringBefore[maxLen];
    signal output curlyDepthBefore[maxLen];
    signal output squareDepthBefore[maxLen];
    signal output depthBefore[maxLen];

    component lengthBits = Num2Bits(LEN_BITS);
    lengthBits.in <== jsonLength;

    component lengthAtLeastTwo = GreaterEqThan(LEN_BITS);
    lengthAtLeastTwo.in[0] <== jsonLength;
    lengthAtLeastTwo.in[1] <== 2;
    lengthAtLeastTwo.out === 1;

    component lengthWithinMax = LessEqThan(LEN_BITS);
    lengthWithinMax.in[0] <== jsonLength;
    lengthWithinMax.in[1] <== maxLen;
    lengthWithinMax.out === 1;

    signal inString[maxLen + 1];
    signal escaped[maxLen + 1];
    signal curlyDepth[maxLen + 1];
    signal squareDepth[maxLen + 1];

    inString[0] <== 0;
    escaped[0] <== 0;
    curlyDepth[0] <== 0;
    squareDepth[0] <== 0;

    component charBits[maxLen];
    component isActive[maxLen];
    component isQuote[maxLen];
    component isBackslash[maxLen];
    component isOpenCurly[maxLen];
    component isCloseCurly[maxLen];
    component isOpenSquare[maxLen];
    component isCloseSquare[maxLen];
    component curlyPositive[maxLen];
    component squarePositive[maxLen];
    component curlyRange[maxLen + 1];
    component squareRange[maxLen + 1];

    signal unescaped[maxLen];
    signal outsideActive[maxLen];
    signal quoteToggle[maxLen];
    signal openCurly[maxLen];
    signal closeCurly[maxLen];
    signal openSquare[maxLen];
    signal closeSquare[maxLen];
    signal escapeEligible[maxLen];

    for (var i = 0; i < maxLen; i++) {
        charBits[i] = Num2Bits(8);
        charBits[i].in <== json[i];

        isActive[i] = GreaterThan(LEN_BITS);
        isActive[i].in[0] <== jsonLength;
        isActive[i].in[1] <== i;
        active[i] <== isActive[i].out;

        // Decoded bytes outside the declared JSON value must be zero.  This
        // makes jsonLength part of the statement rather than a parsing hint.
        json[i] * (1 - active[i]) === 0;

        inStringBefore[i] <== inString[i];
        curlyDepthBefore[i] <== curlyDepth[i];
        squareDepthBefore[i] <== squareDepth[i];
        depthBefore[i] <== curlyDepth[i] + squareDepth[i];

        isQuote[i] = IsEqual();
        isQuote[i].in[0] <== json[i];
        isQuote[i].in[1] <== 34;

        isBackslash[i] = IsEqual();
        isBackslash[i].in[0] <== json[i];
        isBackslash[i].in[1] <== 92;

        isOpenCurly[i] = IsEqual();
        isOpenCurly[i].in[0] <== json[i];
        isOpenCurly[i].in[1] <== 123;

        isCloseCurly[i] = IsEqual();
        isCloseCurly[i].in[0] <== json[i];
        isCloseCurly[i].in[1] <== 125;

        isOpenSquare[i] = IsEqual();
        isOpenSquare[i].in[0] <== json[i];
        isOpenSquare[i].in[1] <== 91;

        isCloseSquare[i] = IsEqual();
        isCloseSquare[i].in[0] <== json[i];
        isCloseSquare[i].in[1] <== 93;

        unescaped[i] <== 1 - escaped[i];
        outsideActive[i] <== active[i] * (1 - inString[i]);
        // Padding bytes are constrained to zero, so an inactive position can
        // never be a quote; no third multiplicand is needed here.
        quoteToggle[i] <== isQuote[i].out * unescaped[i];
        inString[i + 1] <== inString[i] + quoteToggle[i] - 2 * inString[i] * quoteToggle[i];

        // A backslash only escapes the immediately following character when
        // the backslash itself was not escaped.
        escapeEligible[i] <== inString[i] * unescaped[i];
        escaped[i + 1] <== escapeEligible[i] * isBackslash[i].out;

        openCurly[i] <== outsideActive[i] * isOpenCurly[i].out;
        closeCurly[i] <== outsideActive[i] * isCloseCurly[i].out;
        openSquare[i] <== outsideActive[i] * isOpenSquare[i].out;
        closeSquare[i] <== outsideActive[i] * isCloseSquare[i].out;

        curlyPositive[i] = GreaterThan(LEN_BITS);
        curlyPositive[i].in[0] <== curlyDepth[i];
        curlyPositive[i].in[1] <== 0;
        closeCurly[i] * (1 - curlyPositive[i].out) === 0;

        squarePositive[i] = GreaterThan(LEN_BITS);
        squarePositive[i].in[0] <== squareDepth[i];
        squarePositive[i].in[1] <== 0;
        closeSquare[i] * (1 - squarePositive[i].out) === 0;

        curlyDepth[i + 1] <== curlyDepth[i] + openCurly[i] - closeCurly[i];
        squareDepth[i + 1] <== squareDepth[i] + openSquare[i] - closeSquare[i];

        curlyRange[i] = Num2Bits(LEN_BITS);
        curlyRange[i].in <== curlyDepth[i];
        squareRange[i] = Num2Bits(LEN_BITS);
        squareRange[i].in <== squareDepth[i];
    }

    curlyRange[maxLen] = Num2Bits(LEN_BITS);
    curlyRange[maxLen].in <== curlyDepth[maxLen];
    squareRange[maxLen] = Num2Bits(LEN_BITS);
    squareRange[maxLen].in <== squareDepth[maxLen];

    inString[maxLen] === 0;
    escaped[maxLen] === 0;
    curlyDepth[maxLen] === 0;
    squareDepth[maxLen] === 0;
    json[0] === 123;

    signal lastIndex <== jsonLength - 1;
    signal lastChar <== SelectArrayValue(maxLen)(json, lastIndex, 1);
    lastChar === 125;

    // The fixed profile deliberately accepts a compact, ASCII JSON subset:
    // objects, arrays, unescaped strings and canonical unsigned integers.
    // A real grammar is needed here; balanced braces plus substring searches
    // do not reject escaped-key aliases or malformed member separators.
    component grammar = CompactJsonGrammar(maxLen, 4);
    grammar.json <== json;
    grammar.active <== active;
    grammar.inStringBefore <== inStringBefore;
    grammar.depthBefore <== depthBefore;
}

/// Deterministic grammar for the compact JSON subset used by this profile.
///
/// Container state values:
///   0 fresh container; 1 object key required; 2 colon required;
///   3 value required; 4 value complete; 5 in key string;
///   6 in value string; 7 complete zero integer; 8 in non-zero integer.
///
/// Escapes and whitespace are intentionally excluded.  This is narrower than
/// general JSON, but it prevents a host parser and the circuit from assigning
/// different meanings to the same signed bytes.
template CompactJsonGrammar(maxLen, maxDepth) {
    signal input json[maxLen];
    signal input active[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];

    component byteBits[maxLen];
    component ascii[maxLen];
    component printable[maxLen];
    component isQuote[maxLen];
    component isBackslash[maxLen];
    component isOpenCurly[maxLen];
    component isCloseCurly[maxLen];
    component isOpenSquare[maxLen];
    component isCloseSquare[maxLen];
    component isColon[maxLen];
    component isComma[maxLen];
    component isZeroDigit[maxLen];
    component digitLo[maxLen];
    component digitHi[maxLen];
    component depthEq[maxDepth + 1][maxLen];

    signal isDigit[maxLen];
    signal nonZeroDigit[maxLen];
    signal outside[maxLen];
    signal inside[maxLen];
    signal allowedOutside[maxLen];
    signal depthInRange[maxLen];
    signal depthEqAcc[maxLen][maxDepth + 2];
    signal outsideAtDepth[maxDepth + 1][maxLen];
    signal insideAtDepth[maxDepth + 1][maxLen];
    signal rootLevelToken[maxLen];

    for (var i = 0; i < maxLen; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== json[i];
        ascii[i] = LessThan(8);
        ascii[i].in[0] <== json[i];
        ascii[i].in[1] <== 128;
        active[i] * (1 - ascii[i].out) === 0;

        printable[i] = GreaterEqThan(8);
        printable[i].in[0] <== json[i];
        printable[i].in[1] <== 32;
        inside[i] <== active[i] * inStringBefore[i];
        inside[i] * (1 - printable[i].out) === 0;
        outside[i] <== active[i] * (1 - inStringBefore[i]);

        isQuote[i] = IsEqual(); isQuote[i].in[0] <== json[i]; isQuote[i].in[1] <== 34;
        isBackslash[i] = IsEqual(); isBackslash[i].in[0] <== json[i]; isBackslash[i].in[1] <== 92;
        isOpenCurly[i] = IsEqual(); isOpenCurly[i].in[0] <== json[i]; isOpenCurly[i].in[1] <== 123;
        isCloseCurly[i] = IsEqual(); isCloseCurly[i].in[0] <== json[i]; isCloseCurly[i].in[1] <== 125;
        isOpenSquare[i] = IsEqual(); isOpenSquare[i].in[0] <== json[i]; isOpenSquare[i].in[1] <== 91;
        isCloseSquare[i] = IsEqual(); isCloseSquare[i].in[0] <== json[i]; isCloseSquare[i].in[1] <== 93;
        isColon[i] = IsEqual(); isColon[i].in[0] <== json[i]; isColon[i].in[1] <== 58;
        isComma[i] = IsEqual(); isComma[i].in[0] <== json[i]; isComma[i].in[1] <== 44;
        isZeroDigit[i] = IsEqual(); isZeroDigit[i].in[0] <== json[i]; isZeroDigit[i].in[1] <== 48;
        digitLo[i] = GreaterEqThan(8); digitLo[i].in[0] <== json[i]; digitLo[i].in[1] <== 48;
        digitHi[i] = LessEqThan(8); digitHi[i].in[0] <== json[i]; digitHi[i].in[1] <== 57;
        isDigit[i] <== digitLo[i].out * digitHi[i].out;
        nonZeroDigit[i] <== isDigit[i] - isZeroDigit[i].out;

        // No JSON escapes are admitted anywhere in this fixed profile.  This
        // rules out such aliases as "birthd\\u0061te" before key matching.
        active[i] * isBackslash[i].out === 0;

        allowedOutside[i] <== isQuote[i].out + isOpenCurly[i].out + isCloseCurly[i].out
            + isOpenSquare[i].out + isCloseSquare[i].out + isColon[i].out
            + isComma[i].out + isDigit[i];
        outside[i] * (1 - allowedOutside[i]) === 0;

        depthEqAcc[i][0] <== 0;
        for (var d = 0; d <= maxDepth; d++) {
            depthEq[d][i] = IsEqual();
            depthEq[d][i].in[0] <== depthBefore[i];
            depthEq[d][i].in[1] <== d;
            depthEqAcc[i][d + 1] <== depthEqAcc[i][d] + depthEq[d][i].out;
            outsideAtDepth[d][i] <== outside[i] * depthEq[d][i].out;
            insideAtDepth[d][i] <== inside[i] * depthEq[d][i].out;
        }
        depthInRange[i] <== depthEqAcc[i][maxDepth + 1];
        active[i] * (1 - depthInRange[i]) === 0;

        rootLevelToken[i] <== outsideAtDepth[0][i];
        if (i == 0) {
            rootLevelToken[i] === 1;
            isOpenCurly[i].out === 1;
        } else {
            // A second root value after the first object is never valid JSON.
            rootLevelToken[i] === 0;
        }
    }

    signal containerType[maxDepth][maxLen + 1]; // 0 none, 1 object, 2 array
    signal parserState[maxDepth][maxLen + 1];
    for (var d = 0; d < maxDepth; d++) {
        containerType[d][0] <== 0;
        parserState[d][0] <== 0;
    }

    component typeNone[maxDepth][maxLen];
    component typeObject[maxDepth][maxLen];
    component typeArray[maxDepth][maxLen];
    component stateEq[maxDepth][maxLen][9];

    signal atCurrentDepth[maxDepth][maxLen];
    signal outsideCurrent[maxDepth][maxLen];
    signal insideCurrent[maxDepth][maxLen];
    signal initObject[maxDepth][maxLen];
    signal initArray[maxDepth][maxLen];
    signal initAny[maxDepth][maxLen];
    signal closeObject[maxDepth][maxLen];
    signal closeArray[maxDepth][maxLen];
    signal closeAny[maxDepth][maxLen];
    signal openChild[maxDepth][maxLen];
    signal quoteOpen[maxDepth][maxLen];
    signal quoteClose[maxDepth][maxLen];
    signal colonToken[maxDepth][maxLen];
    signal commaToken[maxDepth][maxLen];
    signal digitToken[maxDepth][maxLen];
    signal stateKeyLike[maxDepth][maxLen];
    signal stateArrayValueLike[maxDepth][maxLen];
    signal keyExpected[maxDepth][maxLen];
    signal objectValueExpected[maxDepth][maxLen];
    signal arrayValueExpected[maxDepth][maxLen];
    signal valueExpected[maxDepth][maxLen];
    signal valueEndable[maxDepth][maxLen];
    signal closeObjectAllowed[maxDepth][maxLen];
    signal closeArrayAllowed[maxDepth][maxLen];
    signal quoteOpenAllowed[maxDepth][maxLen];
    signal quoteCloseAllowed[maxDepth][maxLen];
    signal colonAllowed[maxDepth][maxLen];
    signal containerPresent[maxDepth][maxLen];
    signal commaAllowed[maxDepth][maxLen];
    signal digitAllowed[maxDepth][maxLen];
    signal validState[maxDepth][maxLen];
    signal stateUpdate[maxDepth][maxLen];
    signal stateTarget[maxDepth][maxLen];
    signal quoteOpenRole[maxDepth][maxLen];
    signal quoteOpenContribution[maxDepth][maxLen];
    signal quoteCloseRole[maxDepth][maxLen];
    signal quoteCloseContribution[maxDepth][maxLen];
    signal commaRole[maxDepth][maxLen];
    signal commaContribution[maxDepth][maxLen];
    signal digitStartZero[maxDepth][maxLen];
    signal digitStartNonZero[maxDepth][maxLen];
    signal digitRole[maxDepth][maxLen];
    signal digitContribution[maxDepth][maxLen];
    signal typeUpdate[maxDepth][maxLen];

    for (var d = 0; d < maxDepth; d++) {
        for (var i = 0; i < maxLen; i++) {
            typeNone[d][i] = IsEqual(); typeNone[d][i].in[0] <== containerType[d][i]; typeNone[d][i].in[1] <== 0;
            typeObject[d][i] = IsEqual(); typeObject[d][i].in[0] <== containerType[d][i]; typeObject[d][i].in[1] <== 1;
            typeArray[d][i] = IsEqual(); typeArray[d][i].in[0] <== containerType[d][i]; typeArray[d][i].in[1] <== 2;
            typeNone[d][i].out + typeObject[d][i].out + typeArray[d][i].out === 1;

            for (var s = 0; s < 9; s++) {
                stateEq[d][i][s] = IsEqual();
                stateEq[d][i][s].in[0] <== parserState[d][i];
                stateEq[d][i][s].in[1] <== s;
            }
            validState[d][i] <== stateEq[d][i][0].out + stateEq[d][i][1].out
                + stateEq[d][i][2].out + stateEq[d][i][3].out
                + stateEq[d][i][4].out + stateEq[d][i][5].out
                + stateEq[d][i][6].out + stateEq[d][i][7].out
                + stateEq[d][i][8].out;
            validState[d][i] === 1;

            atCurrentDepth[d][i] <== outsideAtDepth[d + 1][i] + insideAtDepth[d + 1][i];
            outsideCurrent[d][i] <== outsideAtDepth[d + 1][i];
            insideCurrent[d][i] <== insideAtDepth[d + 1][i];

            initObject[d][i] <== outsideAtDepth[d][i] * isOpenCurly[i].out;
            initArray[d][i] <== outsideAtDepth[d][i] * isOpenSquare[i].out;
            initAny[d][i] <== initObject[d][i] + initArray[d][i];
            initAny[d][i] * (1 - typeNone[d][i].out) === 0;
            initAny[d][i] * (1 - stateEq[d][i][0].out) === 0;

            closeObject[d][i] <== outsideCurrent[d][i] * isCloseCurly[i].out;
            closeArray[d][i] <== outsideCurrent[d][i] * isCloseSquare[i].out;
            closeAny[d][i] <== closeObject[d][i] + closeArray[d][i];
            openChild[d][i] <== outsideCurrent[d][i] * (isOpenCurly[i].out + isOpenSquare[i].out);
            quoteOpen[d][i] <== outsideCurrent[d][i] * isQuote[i].out;
            quoteClose[d][i] <== insideCurrent[d][i] * isQuote[i].out;
            colonToken[d][i] <== outsideCurrent[d][i] * isColon[i].out;
            commaToken[d][i] <== outsideCurrent[d][i] * isComma[i].out;
            digitToken[d][i] <== outsideCurrent[d][i] * isDigit[i];

            // Every byte inside a string must remain in the role selected by
            // its opening quote; arbitrary quotes cannot reset the parser.
            insideCurrent[d][i] * (1 - stateEq[d][i][5].out - stateEq[d][i][6].out) === 0;

            stateKeyLike[d][i] <== stateEq[d][i][0].out + stateEq[d][i][1].out;
            stateArrayValueLike[d][i] <== stateEq[d][i][0].out + stateEq[d][i][3].out;
            keyExpected[d][i] <== typeObject[d][i].out * stateKeyLike[d][i];
            objectValueExpected[d][i] <== typeObject[d][i].out * stateEq[d][i][3].out;
            arrayValueExpected[d][i] <== typeArray[d][i].out * stateArrayValueLike[d][i];
            valueExpected[d][i] <== objectValueExpected[d][i] + arrayValueExpected[d][i];
            valueEndable[d][i] <== stateEq[d][i][4].out + stateEq[d][i][7].out + stateEq[d][i][8].out;

            closeObjectAllowed[d][i] <== typeObject[d][i].out * (stateEq[d][i][0].out + valueEndable[d][i]);
            closeArrayAllowed[d][i] <== typeArray[d][i].out * (stateEq[d][i][0].out + valueEndable[d][i]);
            quoteOpenAllowed[d][i] <== keyExpected[d][i] + valueExpected[d][i];
            quoteCloseAllowed[d][i] <== stateEq[d][i][5].out + stateEq[d][i][6].out;
            colonAllowed[d][i] <== typeObject[d][i].out * stateEq[d][i][2].out;
            containerPresent[d][i] <== typeObject[d][i].out + typeArray[d][i].out;
            commaAllowed[d][i] <== containerPresent[d][i] * valueEndable[d][i];
            digitAllowed[d][i] <== valueExpected[d][i] + stateEq[d][i][8].out;

            closeObject[d][i] * (1 - closeObjectAllowed[d][i]) === 0;
            closeArray[d][i] * (1 - closeArrayAllowed[d][i]) === 0;
            openChild[d][i] * (1 - valueExpected[d][i]) === 0;
            quoteOpen[d][i] * (1 - quoteOpenAllowed[d][i]) === 0;
            quoteClose[d][i] * (1 - quoteCloseAllowed[d][i]) === 0;
            colonToken[d][i] * (1 - colonAllowed[d][i]) === 0;
            commaToken[d][i] * (1 - commaAllowed[d][i]) === 0;
            digitToken[d][i] * (1 - digitAllowed[d][i]) === 0;

            // At the active container depth, every outside byte must be one of
            // the transitions above.  This catches missing colons/commas and
            // mismatched closing delimiters instead of merely balancing them.
            outsideCurrent[d][i] === closeAny[d][i] + openChild[d][i]
                + quoteOpen[d][i] + colonToken[d][i] + commaToken[d][i]
                + digitToken[d][i];

            stateUpdate[d][i] <== initAny[d][i] + closeAny[d][i] + openChild[d][i]
                + quoteOpen[d][i] + quoteClose[d][i] + colonToken[d][i]
                + commaToken[d][i] + digitToken[d][i];
            stateUpdate[d][i] * (1 - stateUpdate[d][i]) === 0;

            quoteOpenRole[d][i] <== keyExpected[d][i] * 5 + valueExpected[d][i] * 6;
            quoteOpenContribution[d][i] <== quoteOpen[d][i] * quoteOpenRole[d][i];
            quoteCloseRole[d][i] <== stateEq[d][i][5].out * 2 + stateEq[d][i][6].out * 4;
            quoteCloseContribution[d][i] <== quoteClose[d][i] * quoteCloseRole[d][i];
            commaRole[d][i] <== typeObject[d][i].out + typeArray[d][i].out * 3;
            commaContribution[d][i] <== commaToken[d][i] * commaRole[d][i];
            digitStartZero[d][i] <== valueExpected[d][i] * isZeroDigit[i].out;
            digitStartNonZero[d][i] <== valueExpected[d][i] * nonZeroDigit[i];
            digitRole[d][i] <== digitStartZero[d][i] * 7
                + (digitStartNonZero[d][i] + stateEq[d][i][8].out) * 8;
            digitContribution[d][i] <== digitToken[d][i] * digitRole[d][i];
            stateTarget[d][i] <== openChild[d][i] * 4
                + quoteOpenContribution[d][i] + quoteCloseContribution[d][i]
                + colonToken[d][i] * 3 + commaContribution[d][i]
                + digitContribution[d][i];
            parserState[d][i + 1] <== parserState[d][i] * (1 - stateUpdate[d][i]) + stateTarget[d][i];

            typeUpdate[d][i] <== initAny[d][i] + closeAny[d][i];
            typeUpdate[d][i] * (1 - typeUpdate[d][i]) === 0;
            containerType[d][i + 1] <== containerType[d][i] * (1 - typeUpdate[d][i])
                + initObject[d][i] + initArray[d][i] * 2;
        }

        containerType[d][maxLen] === 0;
        parserState[d][maxLen] === 0;
    }
}

/// Locate one exact compact-JSON key (`"key":`) at targetDepth.  The key
/// bytes are circuit inputs so this component is reusable; callers wire them
/// to constants.  Exactly one occurrence at the requested depth is required.
template JsonUniqueKeyAtDepth(maxLen, keyLen, targetDepth) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    var PATTERN_LEN = keyLen + 3; // opening quote, key, closing quote, colon

    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal output valueStart;

    component startWithin = LessEqThan(LEN_BITS);
    startWithin.in[0] <== keyStart + PATTERN_LEN;
    startWithin.in[1] <== maxLen;
    startWithin.out === 1;

    signal expected[PATTERN_LEN];
    component keyByteBits[keyLen];
    expected[0] <== 34;
    for (var j = 0; j < keyLen; j++) {
        keyByteBits[j] = Num2Bits(8);
        keyByteBits[j].in <== keyBytes[j];
        expected[j + 1] <== keyBytes[j];
    }
    expected[keyLen + 1] <== 34;
    expected[keyLen + 2] <== 58;

    component selectedEq[PATTERN_LEN];
    signal selectedChar[PATTERN_LEN];
    signal selectedMatch[PATTERN_LEN + 1];
    selectedMatch[0] <== 1;
    for (var j = 0; j < PATTERN_LEN; j++) {
        selectedChar[j] <== SelectArrayValue(maxLen)(json, keyStart + j, 1);
        selectedEq[j] = IsEqual();
        selectedEq[j].in[0] <== selectedChar[j];
        selectedEq[j].in[1] <== expected[j];
        selectedMatch[j + 1] <== selectedMatch[j] * selectedEq[j].out;
    }
    selectedMatch[PATTERN_LEN] === 1;

    signal selectedStringState <== SelectArrayValue(maxLen)(inStringBefore, keyStart, 1);
    signal selectedDepth <== SelectArrayValue(maxLen)(depthBefore, keyStart, 1);
    selectedStringState === 0;
    selectedDepth === targetDepth;

    var STARTS = maxLen - PATTERN_LEN + 1;
    component scanEq[STARTS][PATTERN_LEN];
    component scanDepthEq[STARTS];
    signal scanMatch[STARTS][PATTERN_LEN + 1];
    signal occurrence[STARTS];
    signal outsideAtI[STARTS];
    signal structuralMatch[STARTS];
    signal occurrenceAcc[STARTS + 1];
    occurrenceAcc[0] <== 0;

    for (var i = 0; i < STARTS; i++) {
        scanMatch[i][0] <== 1;
        for (var j = 0; j < PATTERN_LEN; j++) {
            scanEq[i][j] = IsEqual();
            scanEq[i][j].in[0] <== json[i + j];
            scanEq[i][j].in[1] <== expected[j];
            scanMatch[i][j + 1] <== scanMatch[i][j] * scanEq[i][j].out;
        }
        scanDepthEq[i] = IsEqual();
        scanDepthEq[i].in[0] <== depthBefore[i];
        scanDepthEq[i].in[1] <== targetDepth;
        outsideAtI[i] <== 1 - inStringBefore[i];
        structuralMatch[i] <== scanMatch[i][PATTERN_LEN] * outsideAtI[i];
        occurrence[i] <== structuralMatch[i] * scanDepthEq[i].out;
        occurrenceAcc[i + 1] <== occurrenceAcc[i] + occurrence[i];
    }
    occurrenceAcc[STARTS] === 1;
    valueStart <== keyStart + PATTERN_LEN;
}

template JsonStringField(maxLen, keyLen, maxValueLen, targetDepth) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    var VALUE_BITS = log2Ceil(maxValueLen + 1);

    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input value[maxValueLen];
    signal input valueLength;
    signal output afterValue;

    component key = JsonUniqueKeyAtDepth(maxLen, keyLen, targetDepth);
    key.json <== json;
    key.inStringBefore <== inStringBefore;
    key.depthBefore <== depthBefore;
    key.keyBytes <== keyBytes;
    key.keyStart <== keyStart;

    signal openingQuote <== SelectArrayValue(maxLen)(json, key.valueStart, 1);
    openingQuote === 34;

    component valueLenBits = Num2Bits(VALUE_BITS);
    valueLenBits.in <== valueLength;
    component nonEmpty = GreaterEqThan(VALUE_BITS);
    nonEmpty.in[0] <== valueLength;
    nonEmpty.in[1] <== 1;
    nonEmpty.out === 1;
    component valueWithin = LessEqThan(VALUE_BITS);
    valueWithin.in[0] <== valueLength;
    valueWithin.in[1] <== maxValueLen;
    valueWithin.out === 1;

    component endWithin = LessEqThan(LEN_BITS);
    endWithin.in[0] <== key.valueStart + valueLength + 2;
    endWithin.in[1] <== maxLen;
    endWithin.out === 1;

    component enabled[maxValueLen];
    component byteBits[maxValueLen];
    component printable[maxValueLen];
    component notQuote[maxValueLen];
    component notBackslash[maxValueLen];
    signal actual[maxValueLen];
    for (var j = 0; j < maxValueLen; j++) {
        enabled[j] = GreaterThan(VALUE_BITS);
        enabled[j].in[0] <== valueLength;
        enabled[j].in[1] <== j;

        byteBits[j] = Num2Bits(8);
        byteBits[j].in <== value[j];
        value[j] * (1 - enabled[j].out) === 0;

        actual[j] <== SelectArrayValue(maxLen)(json, key.valueStart + 1 + j, 1);
        enabled[j].out * (actual[j] - value[j]) === 0;

        printable[j] = GreaterEqThan(8);
        printable[j].in[0] <== value[j];
        printable[j].in[1] <== 32;
        enabled[j].out * (1 - printable[j].out) === 0;

        notQuote[j] = IsEqual();
        notQuote[j].in[0] <== value[j];
        notQuote[j].in[1] <== 34;
        enabled[j].out * notQuote[j].out === 0;

        notBackslash[j] = IsEqual();
        notBackslash[j].in[0] <== value[j];
        notBackslash[j].in[1] <== 92;
        enabled[j].out * notBackslash[j].out === 0;
    }

    signal closingQuote <== SelectArrayValue(maxLen)(json, key.valueStart + 1 + valueLength, 1);
    closingQuote === 34;
    afterValue <== key.valueStart + valueLength + 2;
}

template JsonUintField(maxLen, keyLen, maxDigits, targetDepth) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    var DIGIT_BITS = log2Ceil(maxDigits + 1);

    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input digitLength;
    signal output digits[maxDigits];
    signal output value;
    signal output afterValue;

    component key = JsonUniqueKeyAtDepth(maxLen, keyLen, targetDepth);
    key.json <== json;
    key.inStringBefore <== inStringBefore;
    key.depthBefore <== depthBefore;
    key.keyBytes <== keyBytes;
    key.keyStart <== keyStart;

    component digitLenBits = Num2Bits(DIGIT_BITS);
    digitLenBits.in <== digitLength;
    component nonEmpty = GreaterEqThan(DIGIT_BITS);
    nonEmpty.in[0] <== digitLength;
    nonEmpty.in[1] <== 1;
    nonEmpty.out === 1;
    component within = LessEqThan(DIGIT_BITS);
    within.in[0] <== digitLength;
    within.in[1] <== maxDigits;
    within.out === 1;

    component endWithin = LessThan(LEN_BITS);
    endWithin.in[0] <== key.valueStart + digitLength;
    endWithin.in[1] <== maxLen;
    endWithin.out === 1;

    signal acc[maxDigits + 1];
    acc[0] <== 0;
    component enabled[maxDigits];
    component lower[maxDigits];
    component upper[maxDigits];
    signal actual[maxDigits];
    for (var j = 0; j < maxDigits; j++) {
        enabled[j] = GreaterThan(DIGIT_BITS);
        enabled[j].in[0] <== digitLength;
        enabled[j].in[1] <== j;

        actual[j] <== SelectArrayValue(maxLen)(json, key.valueStart + j, 1);
        digits[j] <== actual[j] * enabled[j].out;

        lower[j] = GreaterEqThan(8);
        lower[j].in[0] <== actual[j];
        lower[j].in[1] <== 48;
        upper[j] = LessEqThan(8);
        upper[j].in[0] <== actual[j];
        upper[j].in[1] <== 57;
        enabled[j].out * (1 - lower[j].out) === 0;
        enabled[j].out * (1 - upper[j].out) === 0;

        // Once digitLength is exhausted the accumulator must hold its value.
        // Multiplying acc by ten unconditionally aliases a short signed value
        // (for example `42`) to `4200000000` when maxDigits is ten.
        acc[j + 1] <== acc[j] + enabled[j].out * (acc[j] * 9 + actual[j] - 48);
    }

    component multipleDigits = GreaterThan(DIGIT_BITS);
    multipleDigits.in[0] <== digitLength;
    multipleDigits.in[1] <== 1;
    signal firstDigit <== SelectArrayValue(maxLen)(json, key.valueStart, 1);
    component firstIsZero = IsEqual();
    firstIsZero.in[0] <== firstDigit;
    firstIsZero.in[1] <== 48;
    multipleDigits.out * firstIsZero.out === 0;

    signal delimiter <== SelectArrayValue(maxLen)(json, key.valueStart + digitLength, 1);
    component isComma = IsEqual();
    isComma.in[0] <== delimiter;
    isComma.in[1] <== 44;
    component isClose = IsEqual();
    isClose.in[0] <== delimiter;
    isClose.in[1] <== 125;
    isComma.out + isClose.out === 1;

    value <== acc[maxDigits];
    afterValue <== key.valueStart + digitLength;
}

/// Proves that a keyed object begins at parentDepth and ends at closeIndex.
/// No earlier closing brace at the same object depth is allowed, so child
/// indices constrained between the returned bounds really belong to it.
template JsonObjectBounds(maxLen, keyLen, parentDepth) {
    var LEN_BITS = log2Ceil(maxLen + 1);

    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input closeIndex;
    signal output openIndex;

    component key = JsonUniqueKeyAtDepth(maxLen, keyLen, parentDepth);
    key.json <== json;
    key.inStringBefore <== inStringBefore;
    key.depthBefore <== depthBefore;
    key.keyBytes <== keyBytes;
    key.keyStart <== keyStart;
    openIndex <== key.valueStart;

    signal openChar <== SelectArrayValue(maxLen)(json, openIndex, 1);
    openChar === 123;
    signal closeChar <== SelectArrayValue(maxLen)(json, closeIndex, 1);
    closeChar === 125;
    signal closeStringState <== SelectArrayValue(maxLen)(inStringBefore, closeIndex, 1);
    closeStringState === 0;
    signal closeDepth <== SelectArrayValue(maxLen)(depthBefore, closeIndex, 1);
    closeDepth === parentDepth + 1;

    component closeWithin = LessThan(LEN_BITS);
    closeWithin.in[0] <== closeIndex;
    closeWithin.in[1] <== maxLen;
    closeWithin.out === 1;
    component ordered = LessThan(LEN_BITS);
    ordered.in[0] <== openIndex;
    ordered.in[1] <== closeIndex;
    ordered.out === 1;

    component afterOpen[maxLen];
    component atOrBeforeClose[maxLen];
    component depthEq[maxLen];
    component isClose[maxLen];
    signal directClose[maxLen];
    signal rangeLeft[maxLen];
    signal structural[maxLen];
    signal right[maxLen];
    signal closeCount[maxLen + 1];
    closeCount[0] <== 0;
    for (var i = 0; i < maxLen; i++) {
        afterOpen[i] = LessThan(LEN_BITS);
        afterOpen[i].in[0] <== openIndex;
        afterOpen[i].in[1] <== i;
        atOrBeforeClose[i] = LessEqThan(LEN_BITS);
        atOrBeforeClose[i].in[0] <== i;
        atOrBeforeClose[i].in[1] <== closeIndex;
        depthEq[i] = IsEqual();
        depthEq[i].in[0] <== depthBefore[i];
        depthEq[i].in[1] <== parentDepth + 1;
        isClose[i] = IsEqual();
        isClose[i].in[0] <== json[i];
        isClose[i].in[1] <== 125;

        rangeLeft[i] <== afterOpen[i].out * atOrBeforeClose[i].out;
        structural[i] <== rangeLeft[i] * (1 - inStringBefore[i]);
        right[i] <== depthEq[i].out * isClose[i].out;
        directClose[i] <== structural[i] * right[i];
        closeCount[i + 1] <== closeCount[i] + directClose[i];
    }
    closeCount[maxLen] === 1;
}

/// Array counterpart to JsonObjectBounds.  It is used for the top-level `_sd`
/// digest array so a digest found in an unrelated array cannot satisfy the
/// disclosure-membership relation.
template JsonArrayBounds(maxLen, keyLen, parentDepth) {
    var LEN_BITS = log2Ceil(maxLen + 1);

    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input closeIndex;
    signal output openIndex;

    component key = JsonUniqueKeyAtDepth(maxLen, keyLen, parentDepth);
    key.json <== json;
    key.inStringBefore <== inStringBefore;
    key.depthBefore <== depthBefore;
    key.keyBytes <== keyBytes;
    key.keyStart <== keyStart;
    openIndex <== key.valueStart;

    signal openChar <== SelectArrayValue(maxLen)(json, openIndex, 1);
    openChar === 91;
    signal closeChar <== SelectArrayValue(maxLen)(json, closeIndex, 1);
    closeChar === 93;
    signal closeStringState <== SelectArrayValue(maxLen)(inStringBefore, closeIndex, 1);
    closeStringState === 0;
    signal closeDepth <== SelectArrayValue(maxLen)(depthBefore, closeIndex, 1);
    closeDepth === parentDepth + 1;

    component closeWithin = LessThan(LEN_BITS);
    closeWithin.in[0] <== closeIndex;
    closeWithin.in[1] <== maxLen;
    closeWithin.out === 1;
    component ordered = LessThan(LEN_BITS);
    ordered.in[0] <== openIndex;
    ordered.in[1] <== closeIndex;
    ordered.out === 1;

    component afterOpen[maxLen];
    component atOrBeforeClose[maxLen];
    component depthEq[maxLen];
    component isClose[maxLen];
    signal directClose[maxLen];
    signal rangeLeft[maxLen];
    signal structural[maxLen];
    signal right[maxLen];
    signal closeCount[maxLen + 1];
    closeCount[0] <== 0;
    for (var i = 0; i < maxLen; i++) {
        afterOpen[i] = LessThan(LEN_BITS);
        afterOpen[i].in[0] <== openIndex;
        afterOpen[i].in[1] <== i;
        atOrBeforeClose[i] = LessEqThan(LEN_BITS);
        atOrBeforeClose[i].in[0] <== i;
        atOrBeforeClose[i].in[1] <== closeIndex;
        depthEq[i] = IsEqual();
        depthEq[i].in[0] <== depthBefore[i];
        depthEq[i].in[1] <== parentDepth + 1;
        isClose[i] = IsEqual();
        isClose[i].in[0] <== json[i];
        isClose[i].in[1] <== 93;

        rangeLeft[i] <== afterOpen[i].out * atOrBeforeClose[i].out;
        structural[i] <== rangeLeft[i] * (1 - inStringBefore[i]);
        right[i] <== depthEq[i].out * isClose[i].out;
        directClose[i] <== structural[i] * right[i];
        closeCount[i + 1] <== closeCount[i] + directClose[i];
    }
    closeCount[maxLen] === 1;
}

/// Exact 43-character digest member in a proven array bound.  `digestStart`
/// points to the member's opening quote.
template JsonDigestArrayMember(maxLen, digestLen) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input digest[digestLen];
    signal input digestStart;
    signal input arrayOpen;
    signal input arrayClose;

    component inside = AssertIndexStrictlyInside(maxLen);
    inside.index <== digestStart;
    inside.openIndex <== arrayOpen;
    inside.closeIndex <== arrayClose;

    signal outside <== SelectArrayValue(maxLen)(inStringBefore, digestStart, 1);
    outside === 0;
    signal memberDepth <== SelectArrayValue(maxLen)(depthBefore, digestStart, 1);
    signal arrayDepth <== SelectArrayValue(maxLen)(depthBefore, arrayOpen, 1);
    memberDepth === arrayDepth + 1;

    signal openingQuote <== SelectArrayValue(maxLen)(json, digestStart, 1);
    openingQuote === 34;
    component digestByteBits[digestLen];
    signal actual[digestLen];
    for (var i = 0; i < digestLen; i++) {
        digestByteBits[i] = Num2Bits(8);
        digestByteBits[i].in <== digest[i];
        actual[i] <== SelectArrayValue(maxLen)(json, digestStart + 1 + i, 1);
        actual[i] === digest[i];
    }
    signal closingQuote <== SelectArrayValue(maxLen)(json, digestStart + 1 + digestLen, 1);
    closingQuote === 34;
    signal delimiter <== SelectArrayValue(maxLen)(json, digestStart + 2 + digestLen, 1);
    component isComma = IsEqual(); isComma.in[0] <== delimiter; isComma.in[1] <== 44;
    component isClose = IsEqual(); isClose.in[0] <== delimiter; isClose.in[1] <== 93;
    isComma.out + isClose.out === 1;

    component endInside = LessEqThan(LEN_BITS);
    endInside.in[0] <== digestStart + digestLen + 2;
    endInside.in[1] <== arrayClose;
    endInside.out === 1;
}

template AssertIndexStrictlyInside(maxLen) {
    var LEN_BITS = log2Ceil(maxLen + 1);
    signal input index;
    signal input openIndex;
    signal input closeIndex;

    component afterOpen = LessThan(LEN_BITS);
    afterOpen.in[0] <== openIndex;
    afterOpen.in[1] <== index;
    afterOpen.out === 1;

    component beforeClose = LessThan(LEN_BITS);
    beforeClose.in[0] <== index;
    beforeClose.in[1] <== closeIndex;
    beforeClose.out === 1;
}

template JsonForbiddenKeyAtDepth(maxLen, keyLen, targetDepth) {
    var PATTERN_LEN = keyLen + 3;
    signal input json[maxLen];
    signal input inStringBefore[maxLen];
    signal input depthBefore[maxLen];
    signal input keyBytes[keyLen];

    signal expected[PATTERN_LEN];
    expected[0] <== 34;
    for (var j = 0; j < keyLen; j++) expected[j + 1] <== keyBytes[j];
    expected[keyLen + 1] <== 34;
    expected[keyLen + 2] <== 58;

    var STARTS = maxLen - PATTERN_LEN + 1;
    component eq[STARTS][PATTERN_LEN];
    component depthEq[STARTS];
    signal matches[STARTS][PATTERN_LEN + 1];
    signal outside[STARTS];
    signal structural[STARTS];
    signal occurrence[STARTS];
    signal count[STARTS + 1];
    count[0] <== 0;
    for (var i = 0; i < STARTS; i++) {
        matches[i][0] <== 1;
        for (var j = 0; j < PATTERN_LEN; j++) {
            eq[i][j] = IsEqual();
            eq[i][j].in[0] <== json[i + j];
            eq[i][j].in[1] <== expected[j];
            matches[i][j + 1] <== matches[i][j] * eq[i][j].out;
        }
        depthEq[i] = IsEqual();
        depthEq[i].in[0] <== depthBefore[i];
        depthEq[i].in[1] <== targetDepth;
        outside[i] <== 1 - inStringBefore[i];
        structural[i] <== matches[i][PATTERN_LEN] * outside[i];
        occurrence[i] <== structural[i] * depthEq[i].out;
        count[i + 1] <== count[i] + occurrence[i];
    }
    count[STARTS] === 0;
}
