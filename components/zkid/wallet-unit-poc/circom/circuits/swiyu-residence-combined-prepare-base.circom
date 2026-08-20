pragma circom 2.2.3;

include "utils/es256.circom";
include "jwt_tx_builder/header-payload-extractor.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/json.circom";
include "swiyu/residence-combined-disclosure.circom";
include "swiyu/p256.circom";
include "swiyu/split-commitments.circom";

/// Experimental residence Prepare A/B relation. It keeps the production
/// issuer-authentication and shared-row contract, but authenticates one exact
/// object-valued disclosure containing both residence predicate inputs.
template SwiyuResidenceCombinedPrepareBase(
    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength
) {
    var maxHeaderLength = (maxB64HeaderLength * 3) \ 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;
    var MAX_STRING = 112;
    var MAX_URI = 160;
    // The frozen A/B fixture's 428-byte payload contains a 39-byte status URI.
    // JsonStringField selects every configured slot even after valueLength, so
    // parsing 160 slots would extend beyond this main's deliberately tight
    // 429-byte decoded-payload array. Parse a 120-byte canonical prefix, force
    // the unused commitment buffer tail to zero, and retain the established
    // 160-byte status-URI commitment interface. The payload bound itself is
    // stricter and is the effective URI-length cap.
    var PARSED_URI = 120;
    var MAX_KEY_B64 = 44;
    var MAX_DIGITS = 10;

    // Only the verifier-resolved issuer key is public. Credential material and
    // parser indices remain private.
    signal input issuerPubKeyX;
    signal input issuerPubKeyY;

    signal input message[maxMessageLength];
    signal input messageLength;
    signal input periodIndex;
    signal input headerJsonLength;
    signal input payloadJsonLength;
    signal input issuerSigR;
    signal input issuerSigSInverse;

    signal input residenceDisclosurePadded[128];
    signal input residenceDisclosureLength;
    signal input residenceDisclosureJsonLength;
    signal input residenceDisclosureSaltLength;
    signal input municipalityDigitLength;

    signal input iss[MAX_STRING];
    signal input issLength;
    signal input kid[MAX_STRING];
    signal input kidLength;
    signal input vct[MAX_STRING];
    signal input vctLength;
    signal input holderXB64[MAX_KEY_B64];
    signal input holderYB64[MAX_KEY_B64];
    signal input statusUri[MAX_URI];
    signal input statusUriLength;
    signal input nbfDigitLength;
    signal input expDigitLength;
    signal input statusIndexDigitLength;
    signal input residenceDisclosureDigestB64[43];

    // Parser indices are untrusted witness hints; every index is checked by the
    // structural selectors and parent-bound assertions below.
    signal input headerAlgKeyStart;
    signal input headerTypKeyStart;
    signal input headerKidKeyStart;
    signal input headerProfileVersionKeyStart;
    signal input payloadIssKeyStart;
    signal input payloadVctKeyStart;
    signal input payloadNbfKeyStart;
    signal input payloadExpKeyStart;
    signal input payloadCnfKeyStart;
    signal input payloadCnfClose;
    signal input payloadJwkKeyStart;
    signal input payloadJwkClose;
    signal input payloadKtyKeyStart;
    signal input payloadCrvKeyStart;
    signal input payloadXKeyStart;
    signal input payloadYKeyStart;
    signal input payloadStatusKeyStart;
    signal input payloadStatusClose;
    signal input payloadStatusListKeyStart;
    signal input payloadStatusListClose;
    signal input payloadStatusUriKeyStart;
    signal input payloadStatusIdxKeyStart;
    signal input payloadSdAlgKeyStart;
    signal input payloadSdKeyStart;
    signal input payloadSdClose;
    signal input payloadResidenceDigestStart;

    // These outputs are reclassified as hidden shared-witness rows by the
    // native Spartan wrapper.
    signal output splitShared[10];
    signal output expressionResult;

    signal signingInputLength <== FindRealMessageLength(maxMessageLength)(message);
    component signingPadding = AssertSha256Padding(maxMessageLength);
    signingPadding.bytes <== message;
    signingPadding.realLength <== signingInputLength;
    signingPadding.paddedLength <== messageLength;

    // Compact JWS uses base64url only (plus the single period separator).
    component beforeSigningEnd[maxMessageLength];
    component isPeriodPosition[maxMessageLength];
    component signingChars[maxMessageLength];
    signal charEnabled[maxMessageLength];
    for (var i = 0; i < maxMessageLength; i++) {
        beforeSigningEnd[i] = GreaterThan(log2Ceil(maxMessageLength + 1));
        beforeSigningEnd[i].in[0] <== signingInputLength;
        beforeSigningEnd[i].in[1] <== i;
        isPeriodPosition[i] = IsEqual();
        isPeriodPosition[i].in[0] <== periodIndex;
        isPeriodPosition[i].in[1] <== i;
        charEnabled[i] <== beforeSigningEnd[i].out * (1 - isPeriodPosition[i].out);
        signingChars[i] = AssertBase64UrlCharStrict();
        signingChars[i].char <== message[i];
        signingChars[i].enabled <== charEnabled[i];
    }

    component issuerPoint = AssertP256Point();
    issuerPoint.x <== issuerPubKeyX;
    issuerPoint.y <== issuerPubKeyY;

    component issuerSignature = ES256(maxMessageLength);
    issuerSignature.message <== message;
    issuerSignature.messageLength <== messageLength;
    issuerSignature.sig_r <== issuerSigR;
    issuerSignature.sig_s_inverse <== issuerSigSInverse;
    issuerSignature.pubKeyX <== issuerPubKeyX;
    issuerSignature.pubKeyY <== issuerPubKeyY;

    component extracted = HeaderPayloadExtractor(
        maxMessageLength,
        maxB64HeaderLength,
        maxB64PayloadLength
    );
    extracted.message <== message;
    extracted.messageLength <== messageLength;
    extracted.periodIndex <== periodIndex;
    signal header[maxHeaderLength] <== extracted.header;
    signal payload[maxPayloadLength] <== extracted.payload;

    component headerLengthRelation = Base64UrlDecodedLength(maxB64HeaderLength, maxHeaderLength);
    headerLengthRelation.encodedLength <== periodIndex;
    headerLengthRelation.decodedLength <== headerJsonLength;
    component payloadLengthRelation = Base64UrlDecodedLength(maxB64PayloadLength, maxPayloadLength);
    payloadLengthRelation.encodedLength <== signingInputLength - periodIndex - 1;
    payloadLengthRelation.decodedLength <== payloadJsonLength;

    // Base64 decoders ignore residual low bits.  Bind the signed compact-JWS
    // spelling to the unique RFC 4648 encoding before interpreting JSON.
    signal encodedHeader[maxB64HeaderLength] <== SelectSubArrayBase64(
        maxMessageLength,
        maxB64HeaderLength
    )(message, 0, periodIndex);
    signal encodedPayload[maxB64PayloadLength] <== SelectSubArrayBase64(
        maxMessageLength,
        maxB64PayloadLength
    )(message, periodIndex + 1, signingInputLength - periodIndex - 1);
    component canonicalHeader = AssertBase64UrlCanonicalTail(maxB64HeaderLength, maxHeaderLength);
    canonicalHeader.encoded <== encodedHeader;
    canonicalHeader.encodedLength <== periodIndex;
    canonicalHeader.decodedLength <== headerJsonLength;
    component canonicalPayload = AssertBase64UrlCanonicalTail(maxB64PayloadLength, maxPayloadLength);
    canonicalPayload.encoded <== encodedPayload;
    canonicalPayload.encodedLength <== signingInputLength - periodIndex - 1;
    canonicalPayload.decodedLength <== payloadJsonLength;

    component headerStructure = JsonStructure(maxHeaderLength);
    headerStructure.json <== header;
    headerStructure.jsonLength <== headerJsonLength;
    component payloadStructure = JsonStructure(maxPayloadLength);
    payloadStructure.json <== payload;
    payloadStructure.jsonLength <== payloadJsonLength;

    // Literal key/value bytes are fixed wires, never prover-controlled inputs.
    signal algKey[3]; algKey[0] <== 97; algKey[1] <== 108; algKey[2] <== 103;
    signal algValue[5]; algValue[0] <== 69; algValue[1] <== 83; algValue[2] <== 50; algValue[3] <== 53; algValue[4] <== 54;
    component alg = JsonStringField(maxHeaderLength, 3, 5, 1);
    alg.json <== header; alg.inStringBefore <== headerStructure.inStringBefore; alg.depthBefore <== headerStructure.depthBefore;
    alg.keyBytes <== algKey; alg.keyStart <== headerAlgKeyStart; alg.value <== algValue; alg.valueLength <== 5;

    signal typKey[3]; typKey[0] <== 116; typKey[1] <== 121; typKey[2] <== 112;
    signal typValue[9]; typValue[0] <== 100; typValue[1] <== 99; typValue[2] <== 43; typValue[3] <== 115; typValue[4] <== 100; typValue[5] <== 45; typValue[6] <== 106; typValue[7] <== 119; typValue[8] <== 116;
    component typ = JsonStringField(maxHeaderLength, 3, 9, 1);
    typ.json <== header; typ.inStringBefore <== headerStructure.inStringBefore; typ.depthBefore <== headerStructure.depthBefore;
    typ.keyBytes <== typKey; typ.keyStart <== headerTypKeyStart; typ.value <== typValue; typ.valueLength <== 9;

    signal kidKey[3]; kidKey[0] <== 107; kidKey[1] <== 105; kidKey[2] <== 100;
    component headerKid = JsonStringField(maxHeaderLength, 3, MAX_STRING, 1);
    headerKid.json <== header; headerKid.inStringBefore <== headerStructure.inStringBefore; headerKid.depthBefore <== headerStructure.depthBefore;
    headerKid.keyBytes <== kidKey; headerKid.keyStart <== headerKidKeyStart; headerKid.value <== kid; headerKid.valueLength <== kidLength;

    signal profileVersionKey[15];
    profileVersionKey[0] <== 112; profileVersionKey[1] <== 114; profileVersionKey[2] <== 111;
    profileVersionKey[3] <== 102; profileVersionKey[4] <== 105; profileVersionKey[5] <== 108;
    profileVersionKey[6] <== 101; profileVersionKey[7] <== 95; profileVersionKey[8] <== 118;
    profileVersionKey[9] <== 101; profileVersionKey[10] <== 114; profileVersionKey[11] <== 115;
    profileVersionKey[12] <== 105; profileVersionKey[13] <== 111; profileVersionKey[14] <== 110;
    signal profileVersionValue[22];
    profileVersionValue[0] <== 115; profileVersionValue[1] <== 119; profileVersionValue[2] <== 105;
    profileVersionValue[3] <== 115; profileVersionValue[4] <== 115; profileVersionValue[5] <== 45;
    profileVersionValue[6] <== 112; profileVersionValue[7] <== 114; profileVersionValue[8] <== 111;
    profileVersionValue[9] <== 102; profileVersionValue[10] <== 105; profileVersionValue[11] <== 108;
    profileVersionValue[12] <== 101; profileVersionValue[13] <== 45; profileVersionValue[14] <== 118;
    profileVersionValue[15] <== 99; profileVersionValue[16] <== 58; profileVersionValue[17] <== 49;
    profileVersionValue[18] <== 46; profileVersionValue[19] <== 48; profileVersionValue[20] <== 46;
    profileVersionValue[21] <== 48;
    component profileVersion = JsonStringField(maxHeaderLength, 15, 22, 1);
    profileVersion.json <== header;
    profileVersion.inStringBefore <== headerStructure.inStringBefore;
    profileVersion.depthBefore <== headerStructure.depthBefore;
    profileVersion.keyBytes <== profileVersionKey;
    profileVersion.keyStart <== headerProfileVersionKeyStart;
    profileVersion.value <== profileVersionValue;
    profileVersion.valueLength <== 22;

    signal critKey[4]; critKey[0] <== 99; critKey[1] <== 114; critKey[2] <== 105; critKey[3] <== 116;
    component noCrit = JsonForbiddenKeyAtDepth(maxHeaderLength, 4, 1);
    noCrit.json <== header; noCrit.inStringBefore <== headerStructure.inStringBefore; noCrit.depthBefore <== headerStructure.depthBefore; noCrit.keyBytes <== critKey;
    signal b64Key[3]; b64Key[0] <== 98; b64Key[1] <== 54; b64Key[2] <== 52;
    component noB64 = JsonForbiddenKeyAtDepth(maxHeaderLength, 3, 1);
    noB64.json <== header; noB64.inStringBefore <== headerStructure.inStringBefore; noB64.depthBefore <== headerStructure.depthBefore; noB64.keyBytes <== b64Key;

    signal issKey[3]; issKey[0] <== 105; issKey[1] <== 115; issKey[2] <== 115;
    component payloadIss = JsonStringField(maxPayloadLength, 3, MAX_STRING, 1);
    payloadIss.json <== payload; payloadIss.inStringBefore <== payloadStructure.inStringBefore; payloadIss.depthBefore <== payloadStructure.depthBefore;
    payloadIss.keyBytes <== issKey; payloadIss.keyStart <== payloadIssKeyStart; payloadIss.value <== iss; payloadIss.valueLength <== issLength;

    signal vctKey[3]; vctKey[0] <== 118; vctKey[1] <== 99; vctKey[2] <== 116;
    component payloadVct = JsonStringField(maxPayloadLength, 3, MAX_STRING, 1);
    payloadVct.json <== payload; payloadVct.inStringBefore <== payloadStructure.inStringBefore; payloadVct.depthBefore <== payloadStructure.depthBefore;
    payloadVct.keyBytes <== vctKey; payloadVct.keyStart <== payloadVctKeyStart; payloadVct.value <== vct; payloadVct.valueLength <== vctLength;

    // Both predicate values must come only from authenticated disclosures.
    signal municipalityKey[26];
    var MUNICIPALITY_KEY[26] = [114,101,115,105,100,101,110,99,101,95,109,117,110,105,99,105,112,97,108,105,116,121,95,98,102,115];
    for (var i = 0; i < 26; i++) municipalityKey[i] <== MUNICIPALITY_KEY[i];
    component noClearMunicipality = JsonForbiddenKeyAtDepth(maxPayloadLength, 26, 1);
    noClearMunicipality.json <== payload;
    noClearMunicipality.inStringBefore <== payloadStructure.inStringBefore;
    noClearMunicipality.depthBefore <== payloadStructure.depthBefore;
    noClearMunicipality.keyBytes <== municipalityKey;

    signal residenceSinceKey[15];
    var RESIDENCE_SINCE_KEY[15] = [114,101,115,105,100,101,110,99,101,95,115,105,110,99,101];
    for (var i = 0; i < 15; i++) residenceSinceKey[i] <== RESIDENCE_SINCE_KEY[i];
    component noClearResidenceSince = JsonForbiddenKeyAtDepth(maxPayloadLength, 15, 1);
    noClearResidenceSince.json <== payload;
    noClearResidenceSince.inStringBefore <== payloadStructure.inStringBefore;
    noClearResidenceSince.depthBefore <== payloadStructure.depthBefore;
    noClearResidenceSince.keyBytes <== residenceSinceKey;

    // The optimized claim itself must also be selectively disclosed rather
    // than duplicated as a clear top-level object in the signed payload.
    signal residenceKey[9];
    var RESIDENCE_KEY[9] = [114,101,115,105,100,101,110,99,101];
    for (var i = 0; i < 9; i++) residenceKey[i] <== RESIDENCE_KEY[i];
    component noClearResidence = JsonForbiddenKeyAtDepth(maxPayloadLength, 9, 1);
    noClearResidence.json <== payload;
    noClearResidence.inStringBefore <== payloadStructure.inStringBefore;
    noClearResidence.depthBefore <== payloadStructure.depthBefore;
    noClearResidence.keyBytes <== residenceKey;

    signal nbfKey[3]; nbfKey[0] <== 110; nbfKey[1] <== 98; nbfKey[2] <== 102;
    component nbf = JsonUintField(maxPayloadLength, 3, MAX_DIGITS, 1);
    nbf.json <== payload; nbf.inStringBefore <== payloadStructure.inStringBefore; nbf.depthBefore <== payloadStructure.depthBefore;
    nbf.keyBytes <== nbfKey; nbf.keyStart <== payloadNbfKeyStart; nbf.digitLength <== nbfDigitLength;

    signal expKey[3]; expKey[0] <== 101; expKey[1] <== 120; expKey[2] <== 112;
    component exp = JsonUintField(maxPayloadLength, 3, MAX_DIGITS, 1);
    exp.json <== payload; exp.inStringBefore <== payloadStructure.inStringBefore; exp.depthBefore <== payloadStructure.depthBefore;
    exp.keyBytes <== expKey; exp.keyStart <== payloadExpKeyStart; exp.digitLength <== expDigitLength;

    signal cnfKey[3]; cnfKey[0] <== 99; cnfKey[1] <== 110; cnfKey[2] <== 102;
    component cnf = JsonObjectBounds(maxPayloadLength, 3, 1);
    cnf.json <== payload; cnf.inStringBefore <== payloadStructure.inStringBefore; cnf.depthBefore <== payloadStructure.depthBefore;
    cnf.keyBytes <== cnfKey; cnf.keyStart <== payloadCnfKeyStart; cnf.closeIndex <== payloadCnfClose;

    signal jwkKey[3]; jwkKey[0] <== 106; jwkKey[1] <== 119; jwkKey[2] <== 107;
    component jwk = JsonObjectBounds(maxPayloadLength, 3, 2);
    jwk.json <== payload; jwk.inStringBefore <== payloadStructure.inStringBefore; jwk.depthBefore <== payloadStructure.depthBefore;
    jwk.keyBytes <== jwkKey; jwk.keyStart <== payloadJwkKeyStart; jwk.closeIndex <== payloadJwkClose;
    component jwkInCnf = AssertIndexStrictlyInside(maxPayloadLength); jwkInCnf.index <== payloadJwkKeyStart; jwkInCnf.openIndex <== cnf.openIndex; jwkInCnf.closeIndex <== payloadCnfClose;
    component jwkCloseInCnf = AssertIndexStrictlyInside(maxPayloadLength); jwkCloseInCnf.index <== payloadJwkClose; jwkCloseInCnf.openIndex <== cnf.openIndex; jwkCloseInCnf.closeIndex <== payloadCnfClose;

    signal ktyKey[3]; ktyKey[0] <== 107; ktyKey[1] <== 116; ktyKey[2] <== 121;
    signal ktyValue[2]; ktyValue[0] <== 69; ktyValue[1] <== 67;
    component kty = JsonStringField(maxPayloadLength, 3, 2, 3);
    kty.json <== payload; kty.inStringBefore <== payloadStructure.inStringBefore; kty.depthBefore <== payloadStructure.depthBefore;
    kty.keyBytes <== ktyKey; kty.keyStart <== payloadKtyKeyStart; kty.value <== ktyValue; kty.valueLength <== 2;
    component ktyInside = AssertIndexStrictlyInside(maxPayloadLength); ktyInside.index <== payloadKtyKeyStart; ktyInside.openIndex <== jwk.openIndex; ktyInside.closeIndex <== payloadJwkClose;

    signal crvKey[3]; crvKey[0] <== 99; crvKey[1] <== 114; crvKey[2] <== 118;
    signal crvValue[5]; crvValue[0] <== 80; crvValue[1] <== 45; crvValue[2] <== 50; crvValue[3] <== 53; crvValue[4] <== 54;
    component crv = JsonStringField(maxPayloadLength, 3, 5, 3);
    crv.json <== payload; crv.inStringBefore <== payloadStructure.inStringBefore; crv.depthBefore <== payloadStructure.depthBefore;
    crv.keyBytes <== crvKey; crv.keyStart <== payloadCrvKeyStart; crv.value <== crvValue; crv.valueLength <== 5;
    component crvInside = AssertIndexStrictlyInside(maxPayloadLength); crvInside.index <== payloadCrvKeyStart; crvInside.openIndex <== jwk.openIndex; crvInside.closeIndex <== payloadJwkClose;

    signal xKey[1]; xKey[0] <== 120;
    component xField = JsonStringField(maxPayloadLength, 1, MAX_KEY_B64, 3);
    xField.json <== payload; xField.inStringBefore <== payloadStructure.inStringBefore; xField.depthBefore <== payloadStructure.depthBefore;
    xField.keyBytes <== xKey; xField.keyStart <== payloadXKeyStart; xField.value <== holderXB64; xField.valueLength <== 43;
    component xInside = AssertIndexStrictlyInside(maxPayloadLength); xInside.index <== payloadXKeyStart; xInside.openIndex <== jwk.openIndex; xInside.closeIndex <== payloadJwkClose;
    signal yKey[1]; yKey[0] <== 121;
    component yField = JsonStringField(maxPayloadLength, 1, MAX_KEY_B64, 3);
    yField.json <== payload; yField.inStringBefore <== payloadStructure.inStringBefore; yField.depthBefore <== payloadStructure.depthBefore;
    yField.keyBytes <== yKey; yField.keyStart <== payloadYKeyStart; yField.value <== holderYB64; yField.valueLength <== 43;
    component yInside = AssertIndexStrictlyInside(maxPayloadLength); yInside.index <== payloadYKeyStart; yInside.openIndex <== jwk.openIndex; yInside.closeIndex <== payloadJwkClose;

    signal holderXCanonical[43];
    signal holderYCanonical[43];
    for (var i = 0; i < 43; i++) {
        holderXCanonical[i] <== holderXB64[i];
        holderYCanonical[i] <== holderYB64[i];
    }
    component holderKey = AssertP256EncodedPoint();
    holderKey.xEncoded <== holderXCanonical;
    holderKey.yEncoded <== holderYCanonical;
    signal statusKey[6]; statusKey[0] <== 115; statusKey[1] <== 116; statusKey[2] <== 97; statusKey[3] <== 116; statusKey[4] <== 117; statusKey[5] <== 115;
    component status = JsonObjectBounds(maxPayloadLength, 6, 1);
    status.json <== payload; status.inStringBefore <== payloadStructure.inStringBefore; status.depthBefore <== payloadStructure.depthBefore;
    status.keyBytes <== statusKey; status.keyStart <== payloadStatusKeyStart; status.closeIndex <== payloadStatusClose;
    signal statusListKey[11];
    statusListKey[0] <== 115; statusListKey[1] <== 116; statusListKey[2] <== 97; statusListKey[3] <== 116; statusListKey[4] <== 117; statusListKey[5] <== 115; statusListKey[6] <== 95; statusListKey[7] <== 108; statusListKey[8] <== 105; statusListKey[9] <== 115; statusListKey[10] <== 116;
    component statusList = JsonObjectBounds(maxPayloadLength, 11, 2);
    statusList.json <== payload; statusList.inStringBefore <== payloadStructure.inStringBefore; statusList.depthBefore <== payloadStructure.depthBefore;
    statusList.keyBytes <== statusListKey; statusList.keyStart <== payloadStatusListKeyStart; statusList.closeIndex <== payloadStatusListClose;
    component listInStatus = AssertIndexStrictlyInside(maxPayloadLength); listInStatus.index <== payloadStatusListKeyStart; listInStatus.openIndex <== status.openIndex; listInStatus.closeIndex <== payloadStatusClose;
    component listCloseInStatus = AssertIndexStrictlyInside(maxPayloadLength); listCloseInStatus.index <== payloadStatusListClose; listCloseInStatus.openIndex <== status.openIndex; listCloseInStatus.closeIndex <== payloadStatusClose;

    signal uriKey[3]; uriKey[0] <== 117; uriKey[1] <== 114; uriKey[2] <== 105;
    signal statusUriParsed[PARSED_URI];
    for (var i = 0; i < PARSED_URI; i++) statusUriParsed[i] <== statusUri[i];
    for (var i = PARSED_URI; i < MAX_URI; i++) statusUri[i] === 0;
    component uri = JsonStringField(maxPayloadLength, 3, PARSED_URI, 3);
    uri.json <== payload; uri.inStringBefore <== payloadStructure.inStringBefore; uri.depthBefore <== payloadStructure.depthBefore;
    uri.keyBytes <== uriKey; uri.keyStart <== payloadStatusUriKeyStart; uri.value <== statusUriParsed; uri.valueLength <== statusUriLength;
    component uriInside = AssertIndexStrictlyInside(maxPayloadLength); uriInside.index <== payloadStatusUriKeyStart; uriInside.openIndex <== statusList.openIndex; uriInside.closeIndex <== payloadStatusListClose;
    signal idxKey[3]; idxKey[0] <== 105; idxKey[1] <== 100; idxKey[2] <== 120;
    component idx = JsonUintField(maxPayloadLength, 3, MAX_DIGITS, 3);
    idx.json <== payload; idx.inStringBefore <== payloadStructure.inStringBefore; idx.depthBefore <== payloadStructure.depthBefore;
    idx.keyBytes <== idxKey; idx.keyStart <== payloadStatusIdxKeyStart; idx.digitLength <== statusIndexDigitLength;
    component idxInside = AssertIndexStrictlyInside(maxPayloadLength); idxInside.index <== payloadStatusIdxKeyStart; idxInside.openIndex <== statusList.openIndex; idxInside.closeIndex <== payloadStatusListClose;

    signal sdAlgKey[7]; sdAlgKey[0] <== 95; sdAlgKey[1] <== 115; sdAlgKey[2] <== 100; sdAlgKey[3] <== 95; sdAlgKey[4] <== 97; sdAlgKey[5] <== 108; sdAlgKey[6] <== 103;
    signal sdAlgValue[7]; sdAlgValue[0] <== 115; sdAlgValue[1] <== 104; sdAlgValue[2] <== 97; sdAlgValue[3] <== 45; sdAlgValue[4] <== 50; sdAlgValue[5] <== 53; sdAlgValue[6] <== 54;
    component sdAlg = JsonStringField(maxPayloadLength, 7, 7, 1);
    sdAlg.json <== payload; sdAlg.inStringBefore <== payloadStructure.inStringBefore; sdAlg.depthBefore <== payloadStructure.depthBefore;
    sdAlg.keyBytes <== sdAlgKey; sdAlg.keyStart <== payloadSdAlgKeyStart; sdAlg.value <== sdAlgValue; sdAlg.valueLength <== 7;
    signal sdKey[3]; sdKey[0] <== 95; sdKey[1] <== 115; sdKey[2] <== 100;
    component sdArray = JsonArrayBounds(maxPayloadLength, 3, 1);
    sdArray.json <== payload; sdArray.inStringBefore <== payloadStructure.inStringBefore; sdArray.depthBefore <== payloadStructure.depthBefore;
    sdArray.keyBytes <== sdKey; sdArray.keyStart <== payloadSdKeyStart; sdArray.closeIndex <== payloadSdClose;
    component residenceDigestMember = JsonDigestArrayMember(maxPayloadLength, 43);
    residenceDigestMember.json <== payload;
    residenceDigestMember.inStringBefore <== payloadStructure.inStringBefore;
    residenceDigestMember.depthBefore <== payloadStructure.depthBefore;
    residenceDigestMember.digest <== residenceDisclosureDigestB64;
    residenceDigestMember.digestStart <== payloadResidenceDigestStart;
    residenceDigestMember.arrayOpen <== sdArray.openIndex;
    residenceDigestMember.arrayClose <== payloadSdClose;

    component residenceDisclosure = SwiyuResidenceCombinedDisclosure();
    residenceDisclosure.encodedPadded <== residenceDisclosurePadded;
    residenceDisclosure.encodedLength <== residenceDisclosureLength;
    residenceDisclosure.decodedLength <== residenceDisclosureJsonLength;
    residenceDisclosure.saltLength <== residenceDisclosureSaltLength;
    residenceDisclosure.municipalityDigitLength <== municipalityDigitLength;

    signal residenceDigestPadded[44];
    for (var i = 0; i < 43; i++) {
        residenceDigestPadded[i] <== residenceDisclosureDigestB64[i];
    }
    residenceDigestPadded[43] <== 0;
    component decodedResidenceDigest = DecodeSD(44, 32);
    decodedResidenceDigest.sdBytes <== residenceDigestPadded;
    decodedResidenceDigest.sdLen <== 43;
    component canonicalResidenceDigest = AssertBase64UrlCanonical32();
    canonicalResidenceDigest.encoded <== residenceDisclosureDigestB64;
    for (var i = 0; i < 32; i++) {
        decodedResidenceDigest.base64Out[i] === residenceDisclosure.digestBytes[i];
    }

    component lookup = SwiyuLookupStaticCommitment(MAX_STRING);
    lookup.iss <== iss; lookup.issLength <== issLength;
    lookup.kid <== kid; lookup.kidLength <== kidLength;
    lookup.vct <== vct; lookup.vctLength <== vctLength;

    component uriHash = SwiyuStatusUriCommitment(MAX_URI);
    uriHash.uri <== statusUri;
    uriHash.uriLength <== statusUriLength;

    splitShared[0] <== holderKey.x;
    splitShared[1] <== holderKey.y;
    // 13 low municipality bits followed by the 17-bit day index.
    splitShared[2] <== residenceDisclosure.municipalityBfs
        + residenceDisclosure.residenceSinceDay1900 * 8192;
    splitShared[3] <== nbf.value;
    splitShared[4] <== exp.value;
    splitShared[5] <== idx.value;
    splitShared[6] <== lookup.hashHi;
    splitShared[7] <== lookup.hashLo;
    splitShared[8] <== uriHash.hashHi;
    splitShared[9] <== uriHash.hashLo;
    expressionResult <== 1;
}
