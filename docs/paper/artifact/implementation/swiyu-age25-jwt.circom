pragma circom 2.2.3;

include "utils/es256.circom";
include "ecdsa/ecdsa.circom";
include "jwt_tx_builder/header-payload-extractor.circom";
include "circomlib/circuits/comparators.circom";
include "swiyu/json.circom";
include "swiyu/disclosure.circom";
include "swiyu/p256.circom";
include "swiyu/yyyymmdd-age.circom";

/// OpenAC presentation of the shared age-25 holder-challenge claim.
///
/// Matches `swiyu.shared.age25-holder-challenge.v0` / EPFL d10 obligations:
///   * issuer ES256 under a verifier-supplied public key
///   * authenticated `birth_date` disclosure (not a clear payload field)
///   * nowDate >= birth_date + 25 * 10000 (YYYYMMDD)
///   * holder P-256 signature over the public challenge
///
/// Intentionally omitted relative to `SwiyuAge18Status`:
///   status / revocation, nbf/exp, metadata hashes, session context digest.
template SwiyuAge25Jwt(
    maxMessageLength,
    maxB64HeaderLength,
    maxB64PayloadLength
) {
    var maxHeaderLength = (maxB64HeaderLength * 3) \ 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) \ 4;
    var MAX_KEY_B64 = 44;

    signal input issuerPubKeyX;
    signal input issuerPubKeyY;
    signal input nowDate;
    signal input challengeHash;

    signal input message[maxMessageLength];
    signal input messageLength;
    signal input periodIndex;
    signal input headerJsonLength;
    signal input payloadJsonLength;
    signal input issuerSigR;
    signal input issuerSigSInverse;

    signal input disclosurePadded[128];
    signal input disclosureLength;
    signal input disclosureJsonLength;
    signal input disclosureSaltLength;

    signal input holderSigR;
    signal input holderSigSInverse;
    signal input holderXB64[MAX_KEY_B64];
    signal input holderYB64[MAX_KEY_B64];
    signal input disclosureDigestB64[43];

    signal input headerAlgKeyStart;
    signal input headerTypKeyStart;
    signal input payloadCnfKeyStart;
    signal input payloadCnfClose;
    signal input payloadJwkKeyStart;
    signal input payloadJwkClose;
    signal input payloadKtyKeyStart;
    signal input payloadCrvKeyStart;
    signal input payloadXKeyStart;
    signal input payloadYKeyStart;
    signal input payloadSdAlgKeyStart;
    signal input payloadSdKeyStart;
    signal input payloadSdClose;
    signal input payloadDigestStart;

    signal output expressionResult;

    signal signingInputLength <== FindRealMessageLength(maxMessageLength)(message);
    component signingPadding = AssertSha256Padding(maxMessageLength);
    signingPadding.bytes <== message;
    signingPadding.realLength <== signingInputLength;
    signingPadding.paddedLength <== messageLength;

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

    signal critKey[4]; critKey[0] <== 99; critKey[1] <== 114; critKey[2] <== 105; critKey[3] <== 116;
    component noCrit = JsonForbiddenKeyAtDepth(maxHeaderLength, 4, 1);
    noCrit.json <== header; noCrit.inStringBefore <== headerStructure.inStringBefore; noCrit.depthBefore <== headerStructure.depthBefore; noCrit.keyBytes <== critKey;
    signal b64Key[3]; b64Key[0] <== 98; b64Key[1] <== 54; b64Key[2] <== 52;
    component noB64 = JsonForbiddenKeyAtDepth(maxHeaderLength, 3, 1);
    noB64.json <== header; noB64.inStringBefore <== headerStructure.inStringBefore; noB64.depthBefore <== headerStructure.depthBefore; noB64.keyBytes <== b64Key;

    signal birthDateKey[10];
    birthDateKey[0] <== 98; birthDateKey[1] <== 105; birthDateKey[2] <== 114;
    birthDateKey[3] <== 116; birthDateKey[4] <== 104; birthDateKey[5] <== 95;
    birthDateKey[6] <== 100; birthDateKey[7] <== 97; birthDateKey[8] <== 116; birthDateKey[9] <== 101;
    component noClearBirthDate = JsonForbiddenKeyAtDepth(maxPayloadLength, 10, 1);
    noClearBirthDate.json <== payload;
    noClearBirthDate.inStringBefore <== payloadStructure.inStringBefore;
    noClearBirthDate.depthBefore <== payloadStructure.depthBefore;
    noClearBirthDate.keyBytes <== birthDateKey;

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
    component holderSignature = ECDSA();
    holderSignature.s_inverse <== holderSigSInverse;
    holderSignature.r <== holderSigR;
    holderSignature.m <== challengeHash;
    holderSignature.pubKeyX <== holderKey.x;
    holderSignature.pubKeyY <== holderKey.y;

    signal sdAlgKey[7]; sdAlgKey[0] <== 95; sdAlgKey[1] <== 115; sdAlgKey[2] <== 100; sdAlgKey[3] <== 95; sdAlgKey[4] <== 97; sdAlgKey[5] <== 108; sdAlgKey[6] <== 103;
    signal sdAlgValue[7]; sdAlgValue[0] <== 115; sdAlgValue[1] <== 104; sdAlgValue[2] <== 97; sdAlgValue[3] <== 45; sdAlgValue[4] <== 50; sdAlgValue[5] <== 53; sdAlgValue[6] <== 54;
    component sdAlg = JsonStringField(maxPayloadLength, 7, 7, 1);
    sdAlg.json <== payload; sdAlg.inStringBefore <== payloadStructure.inStringBefore; sdAlg.depthBefore <== payloadStructure.depthBefore;
    sdAlg.keyBytes <== sdAlgKey; sdAlg.keyStart <== payloadSdAlgKeyStart; sdAlg.value <== sdAlgValue; sdAlg.valueLength <== 7;
    signal sdKey[3]; sdKey[0] <== 95; sdKey[1] <== 115; sdKey[2] <== 100;
    component sdArray = JsonArrayBounds(maxPayloadLength, 3, 1);
    sdArray.json <== payload; sdArray.inStringBefore <== payloadStructure.inStringBefore; sdArray.depthBefore <== payloadStructure.depthBefore;
    sdArray.keyBytes <== sdKey; sdArray.keyStart <== payloadSdKeyStart; sdArray.closeIndex <== payloadSdClose;
    component digestMember = JsonDigestArrayMember(maxPayloadLength, 43);
    digestMember.json <== payload; digestMember.inStringBefore <== payloadStructure.inStringBefore; digestMember.depthBefore <== payloadStructure.depthBefore;
    digestMember.digest <== disclosureDigestB64; digestMember.digestStart <== payloadDigestStart; digestMember.arrayOpen <== sdArray.openIndex; digestMember.arrayClose <== payloadSdClose;

    component disclosure = SwiyuBirthDateDisclosure();
    disclosure.encodedPadded <== disclosurePadded;
    disclosure.encodedLength <== disclosureLength;
    disclosure.decodedLength <== disclosureJsonLength;
    disclosure.saltLength <== disclosureSaltLength;
    signal digestB64Padded[44];
    for (var i = 0; i < 43; i++) digestB64Padded[i] <== disclosureDigestB64[i];
    digestB64Padded[43] <== 0;
    component decodedDigest = DecodeSD(44, 32);
    decodedDigest.sdBytes <== digestB64Padded;
    decodedDigest.sdLen <== 43;
    component canonicalDigest = AssertBase64UrlCanonical32();
    canonicalDigest.encoded <== disclosureDigestB64;
    for (var i = 0; i < 32; i++) decodedDigest.base64Out[i] === disclosure.digestBytes[i];

    component age = YyyymmddAgeAtLeast(25);
    age.birthdateNumeric <== disclosure.birthdateNumeric;
    age.nowDate <== nowDate;
    expressionResult <== age.ok;
}
