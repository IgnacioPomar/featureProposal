package es.zaleos.certificate.renewer.spring.boot.autoconfigure;

import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Pending specification tests for the starter module.
 *
 * <p>These tests are intentionally disabled until the missing requirements from
 * the technical specification are implemented.
 */
@Disabled("Enable these tests when the remaining starter requirements from the specification are implemented.")
class ZaleosCertificatePendingSpecificationTests {

    @Test
    void maintenanceTokensRequireExpIatJtiAndOpClaims() {
        fail("Enable when the maintenance API enforces exp, iat, jti and op claims.");
    }

    @Test
    void uploadEndpointRejectsPayloadWhenSha256ClaimDoesNotMatchBody() {
        fail("Enable when upload requests validate the sha256 claim against the received payload.");
    }

    @Test
    void maintenanceEndpointsSupportImportOnlyAndActivateStagedModes() {
        fail("Enable when import-only and activate-staged modes are implemented.");
    }

    @Test
    void disabledMaintenanceEndpointsAreNotRegisteredAtAll() {
        fail("Enable when disabled endpoints are removed from request mappings instead of returning 404 from the handler.");
    }

    @Test
    void verifierRejectsExpiredOrNonCaCertificatesInsideX5cChains() {
        fail("Enable when x5c validation enforces certificate validity dates and CA constraints.");
    }
}
