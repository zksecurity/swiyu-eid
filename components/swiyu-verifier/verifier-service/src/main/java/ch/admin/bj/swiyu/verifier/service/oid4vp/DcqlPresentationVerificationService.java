package ch.admin.bj.swiyu.verifier.service.oid4vp;

import ch.admin.bj.swiyu.verifier.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.verifier.dto.VerificationPresentationDCQLRequestDto;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationErrorResponseCode;
import ch.admin.bj.swiyu.verifier.common.exception.VerificationException;
import ch.admin.bj.swiyu.verifier.domain.SdJwt;
import ch.admin.bj.swiyu.verifier.domain.management.Management;
import ch.admin.bj.swiyu.verifier.domain.management.dcql.ZkPresentationPolicy;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.DcqlEvaluator;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.PresentationVerifier;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.ZkPresentationVerificationResult;
import ch.admin.bj.swiyu.verifier.service.oid4vp.ports.ZkPresentationVerifier;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static ch.admin.bj.swiyu.verifier.common.exception.VerificationException.submissionError;

/**
 * Application service that evaluates a DCQL presentation request.
 * <p>
 * For each requested credential it verifies VP tokens into {@link SdJwt}, filters by VCT,
 * validates the requested claims, and returns the extracted claims as a JSON string.
 */
@Slf4j
@Component
public class DcqlPresentationVerificationService {

    private final PresentationVerifier presentationVerifier;
    private final DcqlEvaluator dcqlEvaluator;
    private final ObjectMapper objectMapper;
    private final ApplicationProperties applicationProperties;
    private final Optional<ZkPresentationVerifier> zkPresentationVerifier;

    /** Ordinary swiyu constructor: ZK remains disabled. */
    public DcqlPresentationVerificationService(
            PresentationVerifier presentationVerifier,
            DcqlEvaluator dcqlEvaluator,
            ObjectMapper objectMapper,
            ApplicationProperties applicationProperties
    ) {
        this(presentationVerifier, dcqlEvaluator, objectMapper, applicationProperties, Optional.empty());
    }

    /** Spring injects the optional sidecar adapter when it is configured. */
    @Autowired
    public DcqlPresentationVerificationService(
            PresentationVerifier presentationVerifier,
            DcqlEvaluator dcqlEvaluator,
            ObjectMapper objectMapper,
            ApplicationProperties applicationProperties,
            Optional<ZkPresentationVerifier> zkPresentationVerifier
    ) {
        this.presentationVerifier = presentationVerifier;
        this.dcqlEvaluator = dcqlEvaluator;
        this.objectMapper = objectMapper;
        this.applicationProperties = applicationProperties;
        this.zkPresentationVerifier = zkPresentationVerifier;
    }

    /**
     * Processes the DCQL presentation request and returns the validated claims per credential as JSON.
     * <p>
     * Throws a {@link VerificationException} with {@link VerificationErrorResponseCode#INVALID_PRESENTATION_SUBMISSION}
     * if required VP tokens are missing, {@code null}, contain {@code null} entries, do not match the DCQL
     * constraints, if serialization fails, if the {@code vp_token} object itself is missing/{@code null}, or if the
     * given {@link Management} entity has no DCQL query configured (e.g. a legacy verification request that
     * receives a DCQL-formatted wallet response).
     */
    public String process(Management entity, VerificationPresentationDCQLRequestDto request) {
        var dcqlQuery = entity.getDcqlQuery();
        if (dcqlQuery == null) {
            // Happens when a verification request was created without a DCQL query (legacy format)
            // but the wallet nevertheless submits its presentation using the DCQL response format.
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "No DCQL query configured for this verification request");
        }
        var requestedCredentials = dcqlQuery.getCredentials();
        var vpTokens = request.getVpToken();
        if (vpTokens == null) {
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Missing vp_token object in presentation submission");
        }
        var verifiedResponses = new HashMap<String, List<Map<String, Object>>>();
        for (var requestedCredential : requestedCredentials) {
            if (!vpTokens.containsKey(requestedCredential.getId())) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Missing vp token for requested credential id " + requestedCredential.getId());
            }
            var requestedVpTokens = vpTokens.get(requestedCredential.getId());
            if (requestedVpTokens == null) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Vp token entry for requested credential id " + requestedCredential.getId() + " must not be null");
            }
            if (!Boolean.TRUE.equals(requestedCredential.getMultiple()) && requestedVpTokens.size() > 1) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Expected only 1 vp token for " + requestedCredential.getId());
            }

            if (requestedVpTokens.size() > applicationProperties.getMaxVcsAccepted()) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Cannot Accept more than %s vcs received %s".formatted(applicationProperties.getMaxVcsAccepted(), requestedVpTokens.size()));
            }

            if (requestedVpTokens.stream().anyMatch(Objects::isNull)) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Vp token list for requested credential id " + requestedCredential.getId() + " must not contain null entries");
            }

            var zkPolicy = requestedCredential.getZkPresentationPolicy();
            if (zkPolicy != null) {
                if (requestedVpTokens.size() != 1) {
                    throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                            "Expected exactly 1 ZK presentation for " + requestedCredential.getId());
                }
                var verifier = zkPresentationVerifier.orElseThrow(() ->
                        submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                                "ZK presentation verification is not configured"));
                var result = verifier.verify(requestedVpTokens.getFirst(), entity, requestedCredential);
                validateZkResult(zkPolicy, result);
                verifiedResponses.put(requestedCredential.getId(), List.of(toResponseMap(zkPolicy, result)));
                continue;
            }

            var sdJwts = requestedVpTokens.stream()
                    .map(token -> presentationVerifier.verify(token, entity, requestedCredential))
                    .toList();

            sdJwts = dcqlEvaluator.filterByVct(sdJwts, requestedCredential.getMeta());

            if (sdJwts.isEmpty()) {
                throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "No matching SD-JWT for requested credential id " + requestedCredential.getId());
            }

            var sdjwt = sdJwts.getFirst();
            dcqlEvaluator.validateRequestedClaims(sdjwt, requestedCredential.getClaims());
            verifiedResponses.put(requestedCredential.getId(), List.of(sdjwt.getResolvedClaims()));
        }
        return writeAsString(verifiedResponses);
    }

    private void validateZkResult(ZkPresentationPolicy policy, ZkPresentationVerificationResult result) {
        if (result == null
                || !policy.profile().equals(result.profile())
                || !policy.circuitId().equals(result.circuitId())
                || !Objects.equals(policy.statusListSnapshot(), result.statusListSnapshot())) {
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK presentation result does not match the signed policy");
        }
        if (!result.predicateSatisfied()) {
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK presentation predicate was not satisfied");
        }
        if (!result.statusValid()) {
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION,
                    "ZK presentation status was not valid");
        }
    }

    private Map<String, Object> toResponseMap(
            ZkPresentationPolicy policy,
            ZkPresentationVerificationResult result
    ) {
        var response = new LinkedHashMap<String, Object>();
        response.put("profile", result.profile());
        response.put("circuit_id", result.circuitId());
        response.put("cutoff_date", policy.cutoffDate());
        response.put("current_time", policy.currentTime());
        response.put("predicate_satisfied", true);

        var status = new LinkedHashMap<String, Object>();
        status.put("valid", true);
        status.put("mode", "snapshot");
        status.put("status_list_snapshot", result.statusListSnapshot());
        response.put("status", status);
        return response;
    }

    private String writeAsString(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JacksonException e) {
            log.error("Failed to serialize object to string. Message: {}", e.getMessage());
            throw submissionError(VerificationErrorResponseCode.INVALID_PRESENTATION_SUBMISSION, "Failed to serialize object to string"); // NOPMD - ExceptionAsFlowControl
        }
    }
}
