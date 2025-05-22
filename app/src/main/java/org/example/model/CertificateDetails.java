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

    // Constructor with all fields
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
    public String getSubjectDN() {
        return subjectDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public int getVersion() {
        return version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public Date getValidUntil() {
        return validUntil;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public Map<String, String> getSubjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    public boolean isSelfSigned() {
        return selfSigned;
    }

    public boolean isExpired() {
        return expired;
    }

    public boolean isNotYetValid() {
        return notYetValid;
    }

    public TrustStatus getTrustStatus() {
        return trustStatus;
    }

    public RevocationStatus getRevocationStatus() {
        return revocationStatus;
    }

    public String getOcspResponderUrl() {
        return ocspResponderUrl;
    }

    public List<String> getCrlDistributionPoints() {
        return crlDistributionPoints;
    }

    public String getFailureReason() {
        return failureReason;
    }

    // Setters
    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public void setValidUntil(Date validUntil) {
        this.validUntil = validUntil;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public void setSubjectAlternativeNames(Map<String, String> subjectAlternativeNames) {
        this.subjectAlternativeNames = subjectAlternativeNames;
    }

    public void setSelfSigned(boolean selfSigned) {
        this.selfSigned = selfSigned;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public void setNotYetValid(boolean notYetValid) {
        this.notYetValid = notYetValid;
    }

    public void setTrustStatus(TrustStatus trustStatus) {
        this.trustStatus = trustStatus;
    }

    public void setRevocationStatus(RevocationStatus revocationStatus) {
        this.revocationStatus = revocationStatus;
    }

    public void setOcspResponderUrl(String ocspResponderUrl) {
        this.ocspResponderUrl = ocspResponderUrl;
    }

    public void setCrlDistributionPoints(List<String> crlDistributionPoints) {
        this.crlDistributionPoints = crlDistributionPoints;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
}
