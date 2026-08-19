pragma circom 2.2.3;

include "json.circom";
include "p256.circom";

template JsonTopStringHarness(maxLen, keyLen, maxValueLen) {
    signal input json[maxLen];
    signal input jsonLength;
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input value[maxValueLen];
    signal input valueLength;
    signal output ok;

    component structure = JsonStructure(maxLen);
    structure.json <== json;
    structure.jsonLength <== jsonLength;

    component field = JsonStringField(maxLen, keyLen, maxValueLen, 1);
    field.json <== json;
    field.inStringBefore <== structure.inStringBefore;
    field.depthBefore <== structure.depthBefore;
    field.keyBytes <== keyBytes;
    field.keyStart <== keyStart;
    field.value <== value;
    field.valueLength <== valueLength;
    ok <== 1;
}

template JsonTopUintHarness(maxLen, keyLen, maxDigits) {
    signal input json[maxLen];
    signal input jsonLength;
    signal input keyBytes[keyLen];
    signal input keyStart;
    signal input digitLength;
    signal output value;

    component structure = JsonStructure(maxLen);
    structure.json <== json;
    structure.jsonLength <== jsonLength;

    component field = JsonUintField(maxLen, keyLen, maxDigits, 1);
    field.json <== json;
    field.inStringBefore <== structure.inStringBefore;
    field.depthBefore <== structure.depthBefore;
    field.keyBytes <== keyBytes;
    field.keyStart <== keyStart;
    field.digitLength <== digitLength;
    value <== field.value;
}

template JsonForbiddenTopKeyHarness(maxLen, keyLen) {
    signal input json[maxLen];
    signal input jsonLength;
    signal input keyBytes[keyLen];
    signal output ok;

    component structure = JsonStructure(maxLen);
    structure.json <== json;
    structure.jsonLength <== jsonLength;

    component forbidden = JsonForbiddenKeyAtDepth(maxLen, keyLen, 1);
    forbidden.json <== json;
    forbidden.inStringBefore <== structure.inStringBefore;
    forbidden.depthBefore <== structure.depthBefore;
    forbidden.keyBytes <== keyBytes;
    ok <== 1;
}

template CanonicalBase64Url32Harness() {
    signal input encoded[43];
    signal output ok;
    component canonical = AssertBase64UrlCanonical32();
    canonical.encoded <== encoded;
    ok <== 1;
}

template P256PointHarness() {
    signal input x;
    signal input y;
    signal output ok;
    component point = AssertP256Point();
    point.x <== x;
    point.y <== y;
    ok <== point.ok;
}

template P256EncodedPointHarness() {
    signal input xEncoded[43];
    signal input yEncoded[43];
    signal output x;
    signal output y;
    component point = AssertP256EncodedPoint();
    point.xEncoded <== xEncoded;
    point.yEncoded <== yEncoded;
    x <== point.x;
    y <== point.y;
}

template HeaderProfileVersionHarness(maxLen) {
    signal input json[maxLen];
    signal input jsonLength;
    signal input keyStart;
    signal output ok;

    component structure = JsonStructure(maxLen);
    structure.json <== json;
    structure.jsonLength <== jsonLength;

    signal key[15];
    key[0] <== 112; key[1] <== 114; key[2] <== 111; key[3] <== 102; key[4] <== 105;
    key[5] <== 108; key[6] <== 101; key[7] <== 95; key[8] <== 118; key[9] <== 101;
    key[10] <== 114; key[11] <== 115; key[12] <== 105; key[13] <== 111; key[14] <== 110;
    signal value[22];
    value[0] <== 115; value[1] <== 119; value[2] <== 105; value[3] <== 115; value[4] <== 115;
    value[5] <== 45; value[6] <== 112; value[7] <== 114; value[8] <== 111; value[9] <== 102;
    value[10] <== 105; value[11] <== 108; value[12] <== 101; value[13] <== 45; value[14] <== 118;
    value[15] <== 99; value[16] <== 58; value[17] <== 49; value[18] <== 46; value[19] <== 48;
    value[20] <== 46; value[21] <== 48;

    component field = JsonStringField(maxLen, 15, 22, 1);
    field.json <== json;
    field.inStringBefore <== structure.inStringBefore;
    field.depthBefore <== structure.depthBefore;
    field.keyBytes <== key;
    field.keyStart <== keyStart;
    field.value <== value;
    field.valueLength <== 22;
    ok <== 1;
}
