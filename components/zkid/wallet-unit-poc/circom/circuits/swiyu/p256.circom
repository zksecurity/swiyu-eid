pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "../utils/utils.circom";
include "disclosure.circom";

/// Assert a finite affine P-256 point in the circuit's native base field.
template AssertP256Point() {
    var B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    signal input x;
    signal input y;
    signal output ok;

    component xZero = IsZero(); xZero.in <== x;
    component yZero = IsZero(); yZero.in <== y;
    component infinity = AND();
    infinity.a <== xZero.out;
    infinity.b <== yZero.out;
    infinity.out === 0;

    signal xSquared <== x * x;
    signal xCubed <== xSquared * x;
    signal ySquared <== y * y;
    ySquared === xCubed - 3 * x + B;
    ok <== 1;
}

/// Convert exactly 32 big-endian bytes to one canonical P-256 base-field
/// element.  The explicit integer comparison prevents values in [p, 2^256)
/// from aliasing a smaller native-field coordinate.
template P256CoordinateFromBytes() {
    // Spell the limbs directly: a literal equal to the native field modulus
    // would itself reduce to zero before a circuit expression could split it.
    var P_HI = 0xffffffff000000010000000000000000;
    var P_LO = 0x00000000ffffffffffffffffffffffff;

    signal input bytes[32];
    signal output coordinate;

    component byteBits[32];
    for (var i = 0; i < 32; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== bytes[i];
    }

    component high = BytesToNumberBE(16);
    component low = BytesToNumberBE(16);
    for (var i = 0; i < 16; i++) {
        high.in[i] <== bytes[i];
        low.in[i] <== bytes[16 + i];
    }

    component highLt = LessThan(129);
    highLt.in[0] <== high.out;
    highLt.in[1] <== P_HI;
    component highEq = IsEqual();
    highEq.in[0] <== high.out;
    highEq.in[1] <== P_HI;
    component lowLt = LessThan(129);
    lowLt.in[0] <== low.out;
    lowLt.in[1] <== P_LO;
    signal equalHighAndLowLess <== highEq.out * lowLt.out;
    highLt.out + equalHighAndLowLess === 1;

    coordinate <== high.out * (2 ** 128) + low.out;
}

/// Strictly decode and validate the holder JWK's two 32-byte coordinates.
template AssertP256EncodedPoint() {
    signal input xEncoded[43];
    signal input yEncoded[43];
    signal output x;
    signal output y;

    component xCanonical = AssertBase64UrlCanonical32();
    component yCanonical = AssertBase64UrlCanonical32();
    xCanonical.encoded <== xEncoded;
    yCanonical.encoded <== yEncoded;

    signal xPadded[44];
    signal yPadded[44];
    for (var i = 0; i < 43; i++) {
        xPadded[i] <== xEncoded[i];
        yPadded[i] <== yEncoded[i];
    }
    xPadded[43] <== 0;
    yPadded[43] <== 0;

    component xDecoded = DecodeSD(44, 32);
    component yDecoded = DecodeSD(44, 32);
    xDecoded.sdBytes <== xPadded;
    xDecoded.sdLen <== 43;
    yDecoded.sdBytes <== yPadded;
    yDecoded.sdLen <== 43;

    component xCoordinate = P256CoordinateFromBytes();
    component yCoordinate = P256CoordinateFromBytes();
    xCoordinate.bytes <== xDecoded.base64Out;
    yCoordinate.bytes <== yDecoded.base64Out;
    x <== xCoordinate.coordinate;
    y <== yCoordinate.coordinate;

    component point = AssertP256Point();
    point.x <== x;
    point.y <== y;
}
