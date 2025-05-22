package org.example.model;

/**
 * Represents the trust status of an X.509 certificate within a chain.
 * This status indicates how the certificate's trustworthiness was determined.
 */
public enum TrustStatus {
    /**
     * The certificate is trusted because it chains up to a root certificate
     * present in the system's default (or a commonly accepted) trust store.
     */
    TRUSTED_BY_ROOT,

    /**
     * The certificate is trusted because it chains up to a certificate
     * present in a user-specified custom trust store (keystore).
     */
    TRUSTED_BY_CUSTOM_KEYSTORE,

    /**
     * The certificate is explicitly not trusted. This could be due to failing
     * path validation, being self-signed without explicit trust, or other
     * trust-related validation errors.
     */
    NOT_TRUSTED,

    /**
     * The trust status of the certificate could not be determined or has not yet
     * been evaluated. This might be an initial state or the result of an
     * inconclusive validation process.
     */
    UNKNOWN
}
