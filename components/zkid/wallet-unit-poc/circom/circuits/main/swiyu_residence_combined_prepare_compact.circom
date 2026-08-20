pragma circom 2.2.3;

include "../swiyu-residence-combined-prepare-base.circom";

// A/B variant for the exact fixture: 246-character header, 571-character
// payload, and 818-character signing input. Tight decoder/SHA bounds are part
// of the optimization; the two-disclosure control remains 896/248/632.
component main {public[issuerPubKeyX, issuerPubKeyY]} = SwiyuResidenceCombinedPrepareBase(832, 248, 572);
