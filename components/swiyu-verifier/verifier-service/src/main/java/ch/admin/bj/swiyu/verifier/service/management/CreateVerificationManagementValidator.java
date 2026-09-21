package ch.admin.bj.swiyu.verifier.service.management;

import ch.admin.bj.swiyu.verifier.dto.management.CreateVerificationManagementDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.DcqlCredentialDto;
import ch.admin.bj.swiyu.verifier.dto.management.dcql.ZkPresentationPolicyDto;
import lombok.experimental.UtilityClass;
import org.springframework.util.CollectionUtils;

import java.time.LocalDate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.regex.Pattern;

import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.EPFL_CIRCUIT_ID;
import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.EPFL_PROFILE;
import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.OPENAC_AGE25_CIRCUIT_ID;
import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.OPENAC_AGE25_PROFILE;
import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.OPENAC_CIRCUIT_ID;
import static ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy.OPENAC_PROFILE;

/**
 * Validator for CreateVerificationManagementDto requests.
 */
@UtilityClass
public class CreateVerificationManagementValidator {

    private static final String ZK_FORMAT = "dc+sd-jwt";
    private static final String OPENAC_BIRTHDATE_CLAIM = "birthdate";
    private static final String EPFL_BIRTHDATE_CLAIM = "birth_date";
    private static final Pattern SNAPSHOT_ID_PATTERN = Pattern.compile("^[A-Za-z0-9._~:-]+$");
    private static final Pattern HEX64_PATTERN = Pattern.compile("^[0-9a-f]{64}$");
    private static final long MAX_CURRENT_TIME_SKEW_SECONDS = 300;

    /**
     * Validates the CreateVerificationManagementDto request.
     * @param request the request to validate
     * @throws IllegalArgumentException if validation fails
     */
    public void validate(CreateVerificationManagementDto request) {
        if (request == null) {
            throw new IllegalArgumentException("CreateVerificationManagement must not be null");
        }

        var dcqlQueryDto = request.dcqlQuery();
        if (dcqlQueryDto == null) {
            throw new IllegalArgumentException("dcql_query is required");
        }
        if (dcqlQueryDto.credentials().stream().anyMatch(cred -> Boolean.TRUE.equals(cred.multiple()))) {
            // Currently supporting only 1 vp token per credential query
            throw new IllegalArgumentException("multiple credentials in response for a single query not supported");
        }
        if (!CollectionUtils.isEmpty(dcqlQueryDto.credentialSets())) {
            // Not yet supporting credential sets
            throw new IllegalArgumentException("credential sets not yet supported");
        }
        if (dcqlQueryDto.credentials().stream().anyMatch(cred -> cred.meta().vctValues().isEmpty())) {
            throw new IllegalArgumentException("vct_values is required");
        }
        dcqlQueryDto.credentials().forEach(CreateVerificationManagementValidator::validateZkPresentationPolicy);
    }

    private static void validateZkPresentationPolicy(DcqlCredentialDto credential) {
        var policy = credential.xSwiyuZkp();
        if (policy == null) {
            return;
        }

        if (!ZK_FORMAT.equals(credential.format())) {
            throw new IllegalArgumentException("x_swiyu_zkp requires credential format dc+sd-jwt");
        }
        if (Boolean.TRUE.equals(credential.multiple())) {
            throw new IllegalArgumentException("x_swiyu_zkp supports exactly one presentation");
        }
        if (!Boolean.TRUE.equals(credential.requireCryptographicHolderBinding())) {
            throw new IllegalArgumentException("x_swiyu_zkp requires explicit cryptographic holder binding");
        }
        if (!CollectionUtils.isEmpty(credential.claimSets())) {
            throw new IllegalArgumentException("x_swiyu_zkp does not support claim_sets");
        }

        if (EPFL_PROFILE.equals(policy.profile())) {
            validateEpflZkPresentationPolicy(credential, policy);
            return;
        }
        if (OPENAC_AGE25_PROFILE.equals(policy.profile())) {
            validateOpenAcAge25ZkPresentationPolicy(credential, policy);
            return;
        }
        if (OPENAC_PROFILE.equals(policy.profile())) {
            validateOpenAcZkPresentationPolicy(credential, policy);
            return;
        }
        throw new IllegalArgumentException("Unsupported x_swiyu_zkp profile: " + policy.profile());
    }

    private static void validateOpenAcZkPresentationPolicy(
            DcqlCredentialDto credential,
            ZkPresentationPolicyDto policy
    ) {
        validateBirthdateClaim(credential, OPENAC_BIRTHDATE_CLAIM, OPENAC_BIRTHDATE_CLAIM);
        if (!OPENAC_CIRCUIT_ID.equals(policy.circuitId())) {
            throw new IllegalArgumentException("Unsupported x_swiyu_zkp circuit_id: " + policy.circuitId());
        }
        validateCutoffDate(policy.cutoffDate());
        validateStatusListSnapshot(policy.statusListSnapshot());
        validateCurrentTime(policy.currentTime());
        if (policy.nowDate() != null || policy.issuerPubX() != null || policy.issuerPubY() != null) {
            throw new IllegalArgumentException("OpenAC x_swiyu_zkp does not accept EPFL policy fields");
        }
    }

    private static void validateEpflZkPresentationPolicy(
            DcqlCredentialDto credential,
            ZkPresentationPolicyDto policy
    ) {
        validateBirthdateClaim(credential, EPFL_BIRTHDATE_CLAIM, EPFL_BIRTHDATE_CLAIM);
        if (!EPFL_CIRCUIT_ID.equals(policy.circuitId())) {
            throw new IllegalArgumentException("Unsupported x_swiyu_zkp circuit_id: " + policy.circuitId());
        }
        if (policy.cutoffDate() != null || policy.statusListSnapshot() != null || policy.currentTime() != null) {
            throw new IllegalArgumentException("EPFL x_swiyu_zkp does not accept OpenAC status policy fields");
        }
        validateNowDate(policy.nowDate());
        validateIssuerCoordinate(policy.issuerPubX(), "issuer_pub_x");
        validateIssuerCoordinate(policy.issuerPubY(), "issuer_pub_y");
    }

    private static void validateOpenAcAge25ZkPresentationPolicy(
            DcqlCredentialDto credential,
            ZkPresentationPolicyDto policy
    ) {
        validateBirthdateClaim(credential, EPFL_BIRTHDATE_CLAIM, EPFL_BIRTHDATE_CLAIM);
        if (!OPENAC_AGE25_CIRCUIT_ID.equals(policy.circuitId())) {
            throw new IllegalArgumentException("Unsupported x_swiyu_zkp circuit_id: " + policy.circuitId());
        }
        if (policy.cutoffDate() != null || policy.statusListSnapshot() != null || policy.currentTime() != null) {
            throw new IllegalArgumentException("OpenAC age-25 x_swiyu_zkp does not accept status policy fields");
        }
        if (policy.issuerPubX() != null || policy.issuerPubY() != null) {
            throw new IllegalArgumentException("OpenAC age-25 x_swiyu_zkp does not accept EPFL issuer coordinates");
        }
        validateNowDate(policy.nowDate());
    }

    private static void validateBirthdateClaim(DcqlCredentialDto credential, String claimId, String claimPath) {
        var claims = credential.claims();
        if (claims == null || claims.size() != 1) {
            throw new IllegalArgumentException("x_swiyu_zkp requires exactly one birthdate claim");
        }
        var claim = claims.getFirst();
        if (!claimId.equals(claim.id()) || !List.of(claimPath).equals(claim.path())) {
            throw new IllegalArgumentException("x_swiyu_zkp claim must have id and path " + claimPath);
        }
        if (!CollectionUtils.isEmpty(claim.values())) {
            throw new IllegalArgumentException("x_swiyu_zkp birthdate claim must not request a disclosed value");
        }
    }

    private static void validateCutoffDate(String cutoffDate) {
        try {
            var parsed = LocalDate.parse(cutoffDate);
            if (!parsed.toString().equals(cutoffDate)) {
                throw new IllegalArgumentException("x_swiyu_zkp cutoff_date must use YYYY-MM-DD");
            }
            if (parsed.getYear() < 1900 || parsed.getYear() > 2199) {
                throw new IllegalArgumentException("x_swiyu_zkp cutoff_date year must be in 1900..2199");
            }
        } catch (DateTimeParseException | NullPointerException e) {
            throw new IllegalArgumentException("x_swiyu_zkp cutoff_date must be a valid YYYY-MM-DD date", e);
        }
    }

    private static void validateStatusListSnapshot(String snapshotId) {
        if (snapshotId == null || snapshotId.isBlank() || snapshotId.length() > 256
                || !SNAPSHOT_ID_PATTERN.matcher(snapshotId).matches()) {
            throw new IllegalArgumentException("x_swiyu_zkp status_list_snapshot must be an opaque snapshot id");
        }
    }

    private static void validateCurrentTime(Long currentTime) {
        if (currentTime == null || currentTime <= 0) {
            throw new IllegalArgumentException("x_swiyu_zkp current_time must be a Unix timestamp in seconds");
        }
        long serverTime = Instant.now().getEpochSecond();
        if (currentTime < serverTime - MAX_CURRENT_TIME_SKEW_SECONDS
                || currentTime > serverTime + MAX_CURRENT_TIME_SKEW_SECONDS) {
            throw new IllegalArgumentException("x_swiyu_zkp current_time must be within 300 seconds of server time");
        }
    }

    private static void validateNowDate(Integer nowDate) {
        if (nowDate == null || nowDate < 19000101 || nowDate > 21991231) {
            throw new IllegalArgumentException("x_swiyu_zkp now_date must be a plausible YYYYMMDD integer");
        }
        int year = nowDate / 10_000;
        int month = (nowDate / 100) % 100;
        int day = nowDate % 100;
        try {
            var parsed = LocalDate.of(year, month, day);
            if (parsed.getYear() * 10_000 + parsed.getMonthValue() * 100 + parsed.getDayOfMonth() != nowDate) {
                throw new IllegalArgumentException("x_swiyu_zkp now_date must be a valid calendar date");
            }
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("x_swiyu_zkp now_date must be a valid calendar date", e);
        }
    }

    private static void validateIssuerCoordinate(String value, String label) {
        if (value == null || !HEX64_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("x_swiyu_zkp " + label + " must be 64-char lowercase hex");
        }
    }
}
