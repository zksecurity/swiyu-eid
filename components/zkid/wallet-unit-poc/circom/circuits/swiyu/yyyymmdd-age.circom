pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/// EPFL d10 / shared-claim age gate:
///   nowDate >= birthdateNumeric + minYears * 10000
/// where both dates are YYYYMMDD integers.  This is not an ISO cutoff
/// comparison and does not use a day-count year length.
template YyyymmddAgeAtLeastCheck(minYears) {
    assert(minYears >= 0);
    assert(minYears <= 150);

    signal input birthdateNumeric;
    signal input nowDate;
    signal output ok;

    component birthBits = Num2Bits(32);
    birthBits.in <== birthdateNumeric;
    component nowBits = Num2Bits(32);
    nowBits.in <== nowDate;

    signal threshold <== birthdateNumeric + minYears * 10000;
    component cmp = GreaterEqThan(32);
    cmp.in[0] <== nowDate;
    cmp.in[1] <== threshold;
    ok <== cmp.out;
}

template YyyymmddAgeAtLeast(minYears) {
    signal input birthdateNumeric;
    signal input nowDate;
    signal output ok;

    component check = YyyymmddAgeAtLeastCheck(minYears);
    check.birthdateNumeric <== birthdateNumeric;
    check.nowDate <== nowDate;
    ok <== check.ok;
    ok === 1;
}
