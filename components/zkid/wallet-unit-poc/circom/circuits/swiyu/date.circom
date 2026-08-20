pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/// Strict Gregorian YYYY-MM-DD validation for the bounded credential profile.
/// The supported range (1900..2199) covers realistic identity credentials and
/// makes the century leap-year rule explicit: 2000 is leap; 1900 and 2100 are
/// not.  All ten bytes are range constrained ASCII digits/separators.
template IsoDate1900To2199() {
    signal input bytes[10];
    signal output numeric; // YYYYMMDD

    component byteBits[10];
    component digitLower[8];
    component digitUpper[8];
    var DIGIT_POS[8] = [0, 1, 2, 3, 5, 6, 8, 9];

    for (var i = 0; i < 10; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== bytes[i];
    }
    bytes[4] === 45;
    bytes[7] === 45;

    signal d[8];
    for (var i = 0; i < 8; i++) {
        digitLower[i] = GreaterEqThan(8);
        digitLower[i].in[0] <== bytes[DIGIT_POS[i]];
        digitLower[i].in[1] <== 48;
        digitLower[i].out === 1;
        digitUpper[i] = LessEqThan(8);
        digitUpper[i].in[0] <== bytes[DIGIT_POS[i]];
        digitUpper[i].in[1] <== 57;
        digitUpper[i].out === 1;
        d[i] <== bytes[DIGIT_POS[i]] - 48;
    }

    signal year <== d[0] * 1000 + d[1] * 100 + d[2] * 10 + d[3];
    signal month <== d[4] * 10 + d[5];
    signal day <== d[6] * 10 + d[7];

    component yearMin = GreaterEqThan(12);
    yearMin.in[0] <== year;
    yearMin.in[1] <== 1900;
    yearMin.out === 1;
    component yearMax = LessEqThan(12);
    yearMax.in[0] <== year;
    yearMax.in[1] <== 2199;
    yearMax.out === 1;

    component monthMin = GreaterEqThan(4);
    monthMin.in[0] <== month;
    monthMin.in[1] <== 1;
    monthMin.out === 1;
    component monthMax = LessEqThan(4);
    monthMax.in[0] <== month;
    monthMax.in[1] <== 12;
    monthMax.out === 1;

    component dayMin = GreaterEqThan(6);
    dayMin.in[0] <== day;
    dayMin.in[1] <== 1;
    dayMin.out === 1;

    signal lastTwo <== d[2] * 10 + d[3];
    signal divFourQuotient <-- lastTwo \ 4;
    signal modFour <== lastTwo - divFourQuotient * 4;
    component quotientBits = Num2Bits(5);
    quotientBits.in <== divFourQuotient;
    component modBits = Num2Bits(2);
    modBits.in <== modFour;
    component divisibleByFour = IsZero();
    divisibleByFour.in <== modFour;

    component is1900 = IsEqual(); is1900.in[0] <== year; is1900.in[1] <== 1900;
    component is2100 = IsEqual(); is2100.in[0] <== year; is2100.in[1] <== 2100;
    signal excludedCentury <== is1900.out + is2100.out;
    signal isLeap <== divisibleByFour.out * (1 - excludedCentury);

    component monthEq[12];
    for (var i = 0; i < 12; i++) {
        monthEq[i] = IsEqual();
        monthEq[i].in[0] <== month;
        monthEq[i].in[1] <== i + 1;
    }

    // Jan, Mar, May, Jul, Aug, Oct, Dec = 31; Apr, Jun, Sep, Nov = 30.
    signal is31a <== monthEq[0].out + monthEq[2].out + monthEq[4].out;
    signal is31b <== monthEq[6].out + monthEq[7].out + monthEq[9].out + monthEq[11].out;
    signal is31 <== is31a + is31b;
    signal is30 <== monthEq[3].out + monthEq[5].out + monthEq[8].out + monthEq[10].out;
    signal febDays <== 28 + isLeap;
    signal maxDay <== is31 * 31 + is30 * 30 + monthEq[1].out * febDays;

    component dayMax = LessEqThan(6);
    dayMax.in[0] <== day;
    dayMax.in[1] <== maxDay;
    dayMax.out === 1;

    numeric <== year * 10000 + month * 100 + day;
}
