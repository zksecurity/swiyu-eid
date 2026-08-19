pragma circom 2.2.3;

include "../swiyu-nullifier-show.circom";

component main {public[
    scopeDigestHi,
    scopeDigestLo,
    expectedNullifierHi,
    expectedNullifierLo
]} = SwiyuNullifierShow();
