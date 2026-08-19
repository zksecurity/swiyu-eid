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
    void validate_shouldRejectUnsupportedOrStaleZkPolicy() {
        var unsupported = new ZkPresentationPolicyDto(
                "unknown-profile",
                "swiyu_age18_status_2k",
                "2008-07-15",
                "snapshot-2026-07-15",
                Instant.now().getEpochSecond());
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
                currentTime);
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
