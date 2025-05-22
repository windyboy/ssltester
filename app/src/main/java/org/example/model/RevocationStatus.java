package org.example.model;

/**
 * Represents the revocation status of an X.509 certificate.
 * This status is determined through OCSP (Online Certificate Status Protocol)
 * and/or CRL (Certificate Revocation List) checks.
 */
public enum RevocationStatus {
    /**
     * The certificate's revocation status has been checked and it is confirmed
     * to be good (not revoked).
     */
    GOOD,

    /**
     * The certificate has been explicitly revoked by its issuer.
     * Details of the revocation (e.g., reason, date) might be available
     * in the {@link CertificateDetails#getFailureReason()}.
     */
    REVOKED,

    /**
     * The revocation status of the certificate could not be determined.
     * This could be due to various reasons, such as:
     * <ul>
     *   <li>OCSP responder or CRL distribution point is unavailable.</li>
     *   <li>The OCSP response or CRL is malformed or cannot be verified.</li>
     *   <li>The OCSP responder indicates an "unknown" status for the certificate.</li>
     *   <li>An error occurred during the revocation check process.</li>
     * </ul>
     * Further details might be available in {@link CertificateDetails#getFailureReason()}.
     */
    UNKNOWN,

    /**
     * The revocation status of the certificate has not been checked.
     * This typically means that both OCSP and CRL checks were disabled
     * or not applicable for this certificate.
     */
    NOT_CHECKED
}
