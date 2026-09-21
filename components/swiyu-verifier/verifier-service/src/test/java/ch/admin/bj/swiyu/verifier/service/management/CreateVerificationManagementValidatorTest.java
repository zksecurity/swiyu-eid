package ch.admin.bj.swiyu.verifier.service.management;

import ch.admin.bj.swiyu.verifier.dto.management.CreateVerificationManagementDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.DcqlClaimDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.DcqlCredentialDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.DcqlCredentialMetaDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.DcqlQueryDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.ZkPresentationPolicyDto;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CreateVerificationManagementValidatorTest {

    @Test
    void validate_shouldThrow_whenRequestIsNull() {
        assertThrows(IllegalArgumentException.class, () -> CreateVerificationManagementValidator.validate(null));
    }

    @Test
    void validate_shouldThrow_whenDCQLQueryIsNull() {
        var request = createRequest(null);
        assertThrows(IllegalArgumentException.class, () -> CreateVerificationManagementValidator.validate(request));
    }

    @Test
    void validate_shouldThrow_whenDcqlQueryHasMultipleCredentials() {
        List<DcqlCredentialDto> credentials = List.of(
                new DcqlCredentialDto(
                        null, // id
                        null, // format
                        true, // multiple
                        new DcqlCredentialMetaDto(List.of(List.of("vct")), null, null), // meta
                        null, // claims
                        null, // claimSets
                        null, // requireCryptographicHolderBinding
                        null // trustedAuthorities
                )
        );
        var dcqlQuery = new DcqlQueryDto(credentials, List.of());
        var request = createRequest(dcqlQuery);
        assertThrows(IllegalArgumentException.class, () -> CreateVerificationManagementValidator.validate(request));
    }

    @Test
    void validate_shouldNotThrow_whenDcqlQueryIsValid() {
        List<DcqlCredentialDto> credentials = List.of(
                new DcqlCredentialDto(
                        null, // id
                        null, // format
                        false, // multiple
                        new DcqlCredentialMetaDto(null, List.of("vct"), null), // meta
                        null, // claims
                        null, // claimSets
                        null, // requireCryptographicHolderBinding
                        null // trustedAuthorities
                )
        );
        var dcqlQuery = new DcqlQueryDto(credentials, List.of());
        var request = createRequest(dcqlQuery);
        assertDoesNotThrow(() -> CreateVerificationManagementValidator.validate(request));
    }

    @Test
    void validate_shouldAcceptCompleteZkPolicy() {
        assertDoesNotThrow(() -> CreateVerificationManagementValidator.validate(
                createZkRequest(zkPolicy(Instant.now().getEpochSecond()))));
    }

    @Test
    void validate_shouldAcceptEpflProfile() {
        assertDoesNotThrow(() -> CreateVerificationManagementValidator.validate(
                createEpflRequest(epflPolicy())));
    }

    @Test
    void validate_shouldAcceptOpenAcAge25Profile() {
        assertDoesNotThrow(() -> CreateVerificationManagementValidator.validate(
                createEpflRequest(openAcAge25Policy())));
    }

    @Test
    void validate_shouldRejectOpenAcAge25PolicyWithStatusOrIssuerFields() {
        var withStatus = new ZkPresentationPolicyDto(
                "openac-age25-jwt-v0",
                "swiyu_age25_jwt",
                "2008-07-15",
                "snapshot-2026-07-15",
                Instant.now().getEpochSecond(),
                20240101,
                null,
                null);
        var withIssuer = new ZkPresentationPolicyDto(
                "openac-age25-jwt-v0",
                "swiyu_age25_jwt",
                null,
                null,
                null,
                20240101,
                epflIssuerX(),
                epflIssuerY());
        assertThrows(IllegalArgumentException.class,
                () -> CreateVerificationManagementValidator.validate(createEpflRequest(withStatus)));
        assertThrows(IllegalArgumentException.class,
                () -> CreateVerificationManagementValidator.validate(createEpflRequest(withIssuer)));
    }

    @Test
    void validate_shouldRejectEpflPolicyWithOpenAcFields() {
        var mixed = new ZkPresentationPolicyDto(
                "epfl-d10-swiyu-jwt-age25-v0",
                "d10_swiyu_jwt",
                "2008-07-15",
                "snapshot-2026-07-15",
                Instant.now().getEpochSecond(),
                20240101,
                epflIssuerX(),
                epflIssuerY());
        assertThrows(IllegalArgumentException.class,
                () -> CreateVerificationManagementValidator.validate(createEpflRequest(mixed)));
    }

    @Test
    void validate_shouldRejectUnsupportedOrStaleZkPolicy() {
        var unsupported = new ZkPresentationPolicyDto(
                "unknown-profile",
                "swiyu_age18_status_2k",
                "2008-07-15",
                "snapshot-2026-07-15",
                Instant.now().getEpochSecond(),
                null,
                null,
                null);
        var stale = zkPolicy(Instant.now().minusSeconds(301).getEpochSecond());

        assertThrows(IllegalArgumentException.class,
                () -> CreateVerificationManagementValidator.validate(createZkRequest(unsupported)));
        assertThrows(IllegalArgumentException.class,
                () -> CreateVerificationManagementValidator.validate(createZkRequest(stale)));
    }

    private CreateVerificationManagementDto createZkRequest(ZkPresentationPolicyDto policy) {
        var credential = new DcqlCredentialDto(
                "age",
                "dc+sd-jwt",
                false,
                new DcqlCredentialMetaDto(null, List.of("urn:example:identity"), null),
                List.of(new DcqlClaimDto("birthdate", List.of("birthdate"), null)),
                null,
                true,
                null,
                policy);
        return createRequest(new DcqlQueryDto(List.of(credential), List.of()));
    }

    private ZkPresentationPolicyDto zkPolicy(long currentTime) {
        return new ZkPresentationPolicyDto(
                "swiyu-age18-status-2k-v0",
                "swiyu_age18_status_2k",
                "2008-07-15",
                "snapshot-2026-07-15",
                currentTime,
                null,
                null,
                null);
    }

    private ZkPresentationPolicyDto openAcAge25Policy() {
        return new ZkPresentationPolicyDto(
                "openac-age25-jwt-v0",
                "swiyu_age25_jwt",
                null,
                null,
                null,
                20240101,
                null,
                null);
    }

    private ZkPresentationPolicyDto epflPolicy() {
        return new ZkPresentationPolicyDto(
                "epfl-d10-swiyu-jwt-age25-v0",
                "d10_swiyu_jwt",
                null,
                null,
                null,
                20240101,
                epflIssuerX(),
                epflIssuerY());
    }

    private CreateVerificationManagementDto createEpflRequest(ZkPresentationPolicyDto policy) {
        var credential = new DcqlCredentialDto(
                "birth_date",
                "dc+sd-jwt",
                false,
                new DcqlCredentialMetaDto(null, List.of("https://example.ch/vct/epfl-d10-test"), null),
                List.of(new DcqlClaimDto("birth_date", List.of("birth_date"), null)),
                null,
                true,
                null,
                policy);
        return createRequest(new DcqlQueryDto(List.of(credential), List.of()));
    }

    private static String epflIssuerX() {
        return "e14492964d758e7de59e3adade4b3337cdc112e8bd37933c3769a2feb2d44de8";
    }

    private static String epflIssuerY() {
        return "abb82c578d7685444f97c9e59070e65a1810b4a5d82135f8a3c5994dbf39d884";
    }

    private CreateVerificationManagementDto createRequest(DcqlQueryDto dcqlQuery) {
        return new CreateVerificationManagementDto(
                null, // acceptedIssuerDids
                null,
                null, // jwtSecuredAuthorizationRequest
                null, // responseMode
                null, // configuration_override
                dcqlQuery,
                null, // verificationPurpose
                null // redirectUri
        );
    }

}
