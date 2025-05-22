package org.example.model;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Holds detailed information about an X.509 certificate, including its properties,
 * validity, trust status, and revocation status.
 */
public class CertificateDetails {

    /** The distinguished name (DN) of the certificate subject. */
    private String subjectDN;
    /** The distinguished name (DN) of the certificate issuer. */
    private String issuerDN;
    /** The version number of the certificate (e.g., 3 for X.509v3). */
    private int version;
    /** The serial number of the certificate, typically as a hexadecimal string. */
    private String serialNumber;
    /** The date and time from which the certificate is valid. */
    private Date validFrom;
    /** The date and time until which the certificate is valid. */
    private Date validUntil;
    /** The algorithm used to sign the certificate. */
    private String signatureAlgorithm;
    /** The algorithm of the public key contained in the certificate. */
    private String publicKeyAlgorithm;
    /** A map of Subject Alternative Names (SANs), where the key is the SAN type (as a string) and value is the SAN value. */
    private Map<String, String> subjectAlternativeNames;
    /** True if the certificate is self-signed (issuer and subject are the same), false otherwise. */
    private boolean selfSigned;
    /** True if the certificate has expired based on the current date and its 'validUntil' field, false otherwise. */
    private boolean expired;
    /** True if the certificate is not yet valid based on the current date and its 'validFrom' field, false otherwise. */
    private boolean notYetValid;
    /** The overall trust status of the certificate within its chain (e.g., trusted by root, not trusted). */
    private TrustStatus trustStatus;
    /** The revocation status of the certificate (e.g., good, revoked, unknown). */
    private RevocationStatus revocationStatus;
    /** The URL of the OCSP responder used for checking this certificate, if applicable. */
    private String ocspResponderUrl;
    /** A list of CRL distribution point URLs found in the certificate. */
    private List<String> crlDistributionPoints;
    /** A consolidated reason for any failure encountered during validation (trust, revocation, expiry, etc.). */
    private String failureReason;

    /**
     * Default constructor.
     */
    public CertificateDetails() {
    }

    /**
     * Constructs a new CertificateDetails object with all fields initialized.
     *
     * @param subjectDN The distinguished name (DN) of the certificate subject.
     * @param issuerDN The distinguished name (DN) of the certificate issuer.
     * @param version The version number of the certificate.
     * @param serialNumber The serial number of the certificate.
     * @param validFrom The date and time from which the certificate is valid.
     * @param validUntil The date and time until which the certificate is valid.
     * @param signatureAlgorithm The algorithm used to sign the certificate.
     * @param publicKeyAlgorithm The algorithm of the public key.
     * @param subjectAlternativeNames A map of Subject Alternative Names.
     * @param selfSigned True if the certificate is self-signed.
     * @param expired True if the certificate has expired.
     * @param notYetValid True if the certificate is not yet valid.
     * @param trustStatus The overall trust status of the certificate.
     * @param revocationStatus The revocation status of the certificate.
     * @param ocspResponderUrl The OCSP responder URL.
     * @param crlDistributionPoints A list of CRL distribution point URLs.
     * @param failureReason A reason for any validation failure.
     */
    public CertificateDetails(String subjectDN, String issuerDN, int version, String serialNumber,
                              Date validFrom, Date validUntil, String signatureAlgorithm,
                              String publicKeyAlgorithm, Map<String, String> subjectAlternativeNames,
                              boolean selfSigned, boolean expired, boolean notYetValid,
                              TrustStatus trustStatus, RevocationStatus revocationStatus,
                              String ocspResponderUrl, List<String> crlDistributionPoints,
                              String failureReason) {
        this.subjectDN = subjectDN;
        this.issuerDN = issuerDN;
        this.version = version;
        this.serialNumber = serialNumber;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.subjectAlternativeNames = subjectAlternativeNames;
        this.selfSigned = selfSigned;
        this.expired = expired;
        this.notYetValid = notYetValid;
        this.trustStatus = trustStatus;
        this.revocationStatus = revocationStatus;
        this.ocspResponderUrl = ocspResponderUrl;
        this.crlDistributionPoints = crlDistributionPoints;
        this.failureReason = failureReason;
    }

    // Getters

    /**
     * Gets the distinguished name (DN) of the certificate subject.
     * @return The subject DN string.
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * Gets the distinguished name (DN) of the certificate issuer.
     * @return The issuer DN string.
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * Gets the version number of the certificate.
     * @return The certificate version number.
     */
    public int getVersion() {
        return version;
    }

    /**
     * Gets the serial number of the certificate.
     * @return The serial number string (often hexadecimal).
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * Gets the date and time from which the certificate is valid.
     * @return The start validity date.
     */
    public Date getValidFrom() {
        return validFrom;
    }

    /**
     * Gets the date and time until which the certificate is valid.
     * @return The end validity date.
     */
    public Date getValidUntil() {
        return validUntil;
    }

    /**
     * Gets the algorithm used to sign the certificate.
     * @return The signature algorithm string.
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Gets the algorithm of the public key in the certificate.
     * @return The public key algorithm string.
     */
    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    /**
     * Gets the Subject Alternative Names (SANs) from the certificate.
     * @return A map of SANs, where key is type and value is the name.
     */
    public Map<String, String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    /**
     * Checks if the certificate is self-signed.
     * @return True if self-signed, false otherwise.
     */
    public boolean isSelfSigned() {
        return selfSigned;
    }

    /**
     * Checks if the certificate has expired.
     * @return True if expired, false otherwise.
     */
    public boolean isExpired() {
        return expired;
    }

    /**
     * Checks if the certificate is not yet valid.
     * @return True if not yet valid, false otherwise.
     */
    public boolean isNotYetValid() {
        return notYetValid;
    }

    /**
     * Gets the trust status of the certificate.
     * @return The {@link TrustStatus} enum value.
     */
    public TrustStatus getTrustStatus() {
        return trustStatus;
    }

    /**
     * Gets the revocation status of the certificate.
     * @return The {@link RevocationStatus} enum value.
     */
    public RevocationStatus getRevocationStatus() {
        return revocationStatus;
    }

    /**
     * Gets the OCSP responder URL used for this certificate's check.
     * @return The OCSP URL string, or null if not applicable/found.
     */
    public String getOcspResponderUrl() {
        return ocspResponderUrl;
    }

    /**
     * Gets the list of CRL distribution point URLs from the certificate.
     * @return A list of CRL URL strings, or null/empty if none.
     */
    public List<String> getCrlDistributionPoints() {
        return crlDistributionPoints;
    }

    /**
     * Gets the reason for any validation failure.
     * @return The failure reason string, or null if no failure.
     */
    public String getFailureReason() {
        return failureReason;
    }

    // Setters

    /**
     * Sets the subject distinguished name for the certificate.
     * @param subjectDN The subject distinguished name (e.g., "CN=example.com, O=Example Inc").
     */
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * Sets the issuer distinguished name for the certificate.
     * @param issuerDN The issuer distinguished name.
     */
    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * Sets the version number of the certificate.
     * @param version The certificate version.
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * Sets the serial number of the certificate.
     * @param serialNumber The certificate serial number.
     */
    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * Sets the start validity date of the certificate.
     * @param validFrom The date from which the certificate is valid.
     */
    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    /**
     * Sets the end validity date of the certificate.
     * @param validUntil The date until which the certificate is valid.
     */
    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    /**
     * Sets the signature algorithm of the certificate.
     * @param signatureAlgorithm The signature algorithm.
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * Sets the public key algorithm of the certificate.
     * @param publicKeyAlgorithm The public key algorithm.
     */
    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    /**
     * Sets the Subject Alternative Names (SANs) for the certificate.
     * @param subjectAlternativeNames A map of SANs.
     */
    public void setSubjectAlternativeNames(Map<String, String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    /**
     * Sets whether the certificate is self-signed.
     * @param selfSigned True if self-signed, false otherwise.
     */
    public void setSelfSigned(boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    /**
     * Sets whether the certificate has expired.
     * @param expired True if expired, false otherwise.
     */
    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    /**
     * Sets whether the certificate is not yet valid.
     * @param notYetValid True if not yet valid, false otherwise.
     */
    public void setNotYetValid(boolean notYetValid) {
        this.notYetValid = notYetValid;
    }

    /**
     * Sets the trust status of the certificate.
     * @param trustStatus The {@link TrustStatus} value.
     */
    public void setTrustStatus(TrustStatus trustStatus) {
        this.trustStatus = trustStatus;
    }

    /**
     * Sets the revocation status of the certificate.
     * @param revocationStatus The {@link RevocationStatus} value.
     */
    public void setRevocationStatus(RevocationStatus revocationStatus) {
        this.revocationStatus = revocationStatus;
    }

    /**
     * Sets the OCSP responder URL used for this certificate's check.
     * @param ocspResponderUrl The OCSP URL string.
     */
    public void setOcspResponderUrl(String ocspResponderUrl) {
        this.ocspResponderUrl = ocspResponderUrl;
    }

    /**
     * Sets the list of CRL distribution point URLs from the certificate.
     * @param crlDistributionPoints A list of CRL URL strings.
     */
    public void setCrlDistributionPoints(List<String> crlDistributionPoints) {
        this.crlDistributionPoints = crlDistributionPoints;
    }

    /**
     * Sets the reason for any validation failure.
     * @param failureReason The failure reason string.
     */
    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
}
