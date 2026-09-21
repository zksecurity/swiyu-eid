package ch.admin.bj.swiyu.verifier.service.oid4vp.adapters;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EpflChallengeBindingTest {

    private static final String ISSUER_X =
            "853657d2e701215a65c5d97ab3cf5640e9aa8379ac6d106b7c82dc9b9d078e79";
    private static final String ISSUER_Y =
            "9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6";

    @Test
    void deterministicVectorMatchesCrossLanguageFixture() {
        var context = new EpflChallengeBinding.SessionContext(
                "nonce-alpha",
                "did:example:verifier",
                "https://example.test/oid4vp/api/request-object/"
                        + "00000000-0000-4000-8000-000000000001/response-data",
                "state-beta",
                "birth_date",
                EpflChallengeBinding.PROFILE,
                EpflChallengeBinding.CIRCUIT_ID,
                20240101,
                ISSUER_X,
                ISSUER_Y);
        assertEquals(
                "{\"circuit_id\":\"d10_swiyu_jwt\",\"issuer_pub_x\":\""
                        + ISSUER_X + "\",\"issuer_pub_y\":\""
                        + ISSUER_Y + "\",\"now_date\":20240101}",
                EpflChallengeBinding.policyInputsJson(context));
        assertEquals(
                "71904c78267613800be90ce2b62f3ef571de0a94eb2f41d2053d8aa58f528f90",
                EpflChallengeBinding.digestHex(context));
        assertEquals(32, EpflChallengeBinding.digestAsU8List(context).size());
    }

    @Test
    void digestChangesWhenNonceChanges() {
        var base = context("nonce-a");
        var changed = context("nonce-b");
        assertNotEquals(EpflChallengeBinding.digestHex(base), EpflChallengeBinding.digestHex(changed));
    }

    @Test
    void rejectsInvalidIssuerCoordinates() {
        var invalid = new EpflChallengeBinding.SessionContext(
                "nonce-alpha",
                "did:example:verifier",
                "https://example.test/response-data",
                "state-beta",
                "birth_date",
                EpflChallengeBinding.PROFILE,
                EpflChallengeBinding.CIRCUIT_ID,
                20240101,
                "not-hex",
                ISSUER_Y);
        assertThrows(IllegalArgumentException.class, () -> EpflChallengeBinding.digestHex(invalid));
    }

    private static EpflChallengeBinding.SessionContext context(String nonce) {
        return new EpflChallengeBinding.SessionContext(
                nonce,
                "did:example:verifier",
                "https://example.test/response-data",
                "state-beta",
                "birth_date",
                EpflChallengeBinding.PROFILE,
                EpflChallengeBinding.CIRCUIT_ID,
                20240101,
                ISSUER_X,
                ISSUER_Y);
    }
}
