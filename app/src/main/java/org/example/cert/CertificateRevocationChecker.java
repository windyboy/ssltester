package org.example.cert;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cert.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.ocsp.OCSPException;
import org.example.model.CertificateDetails;
import org.example.model.RevocationStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Handles the revocation checking of X.509 certificates using OCSP and CRL mechanisms.
 * It uses Bouncy Castle for cryptographic operations and ASN.1 parsing.
 * The checks are configurable via constructor arguments.
 */
public class CertificateRevocationChecker {
    private static final Logger logger = LoggerFactory.getLogger(CertificateRevocationChecker.class);
    /** Flag indicating whether OCSP checking is enabled. */
    private final boolean checkOCSPEnabled;
    /** Flag indicating whether CRL checking is enabled. */
    private final boolean checkCRLEnabled;

    static {
        // Ensure Bouncy Castle provider is registered for cryptographic operations.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            logger.debug("Bouncy Castle provider registered.");
        } else {
            logger.debug("Bouncy Castle provider already registered.");
        }
    }

    /**
     * Constructs a new CertificateRevocationChecker.
     *
     * @param checkOCSP True to enable OCSP checks, false to disable.
     * @param checkCRL  True to enable CRL checks, false to disable.
     */
    public CertificateRevocationChecker(boolean checkOCSP, boolean checkCRL) {
        this.checkOCSPEnabled = checkOCSP;
        this.checkCRLEnabled = checkCRL;
        logger.info("CertificateRevocationChecker initialized. OCSP enabled: {}, CRL enabled: {}", checkOCSP, checkCRL);
    }

    /**
     * Checks the revocation status of the given certificate using OCSP and/or CRL,
     * based on the checker's configuration.
     * The results, including status and any failure reasons, are populated into the
     * {@code detailsToUpdate} object.
     *
     * @param cert             The certificate to check. Must not be null.
     * @param issuerCert       The issuer certificate of {@code cert}. Required for OCSP and CRL signature verification.
     *                         Can be null if the certificate is self-signed and is its own issuer.
     * @param detailsToUpdate  The {@link CertificateDetails} object to populate with revocation information. Must not be null.
     */
    public void checkRevocation(X509Certificate cert, X509Certificate issuerCert, CertificateDetails detailsToUpdate) {
        String certId = "Cert Subject: " + (cert != null ? cert.getSubjectX500Principal().getName() : "null") +
                        ", Serial: " + (cert != null ? cert.getSerialNumber() : "null");
        logger.debug("Initiating revocation check for {}.", certId);

        if (cert == null) {
            logger.warn("Certificate to check is null. Skipping revocation check for {}.", certId);
            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
            detailsToUpdate.setFailureReason("Certificate to check was null.");
            return;
        }
        if (detailsToUpdate == null) {
            // This case should ideally not happen if called correctly.
            logger.error("CertificateDetails object is null for {}. Cannot update status.", certId);
            return;
        }

        // Initialize with a baseline UNKNOWN, to be updated by specific checks.
        detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
        detailsToUpdate.setFailureReason(null); // Clear any prior reasons

        boolean ocspAttempted = false;
        if (checkOCSPEnabled) {
            ocspAttempted = true;
            logger.debug("Attempting OCSP check for {}.", certId);
            if (issuerCert == null) {
                logger.warn("Issuer certificate is null for {}. Skipping OCSP check.", certId);
                detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                detailsToUpdate.setFailureReason("Issuer certificate not provided for OCSP check.");
            } else {
                try {
                    checkOCSP(cert, issuerCert, detailsToUpdate);
                } catch (Exception e) { // Catching generic Exception to be safe, specific ones preferred
                    logger.error("Exception during OCSP check for {}: {}", certId, e.getMessage(), e);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "OCSP check threw an exception: " + e.getMessage()));
                }
            }
        } else {
             logger.info("OCSP check is disabled for {}.", certId);
        }

        // Determine if CRL check should proceed
        boolean shouldCheckCrl = checkCRLEnabled;
        if (ocspAttempted && detailsToUpdate.getRevocationStatus() == RevocationStatus.GOOD) {
            logger.info("OCSP status is GOOD for {}. CRL check will be skipped.", certId);
            shouldCheckCrl = false; 
        } else if (ocspAttempted && detailsToUpdate.getRevocationStatus() == RevocationStatus.REVOKED) {
            logger.info("OCSP status is REVOKED for {}. CRL check will be skipped.", certId);
            shouldCheckCrl = false;
        } else if (ocspAttempted) { // OCSP was attempted but result was UNKNOWN or some error
            logger.info("OCSP status for {} is {}. Proceeding to CRL check if enabled.", certId, detailsToUpdate.getRevocationStatus());
        }


        if (shouldCheckCrl) {
            logger.debug("Attempting CRL check for {}.", certId);
            if (issuerCert == null) {
                 logger.warn("Issuer certificate is null for {}. Skipping CRL check.", certId);
                 // Only set to UNKNOWN if OCSP didn't already determine a status or also failed due to no issuer
                 if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN || detailsToUpdate.getRevocationStatus() == RevocationStatus.NOT_CHECKED) {
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"Issuer certificate not provided for CRL check."));
                 }
            } else {
                try {
                    checkCRL(cert, issuerCert, detailsToUpdate);
                } catch (Exception e) { // Catching generic Exception
                    logger.error("Exception during CRL check for {}: {}", certId, e.getMessage(), e);
                    if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN || detailsToUpdate.getRevocationStatus() == RevocationStatus.NOT_CHECKED) {
                        detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                        detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"CRL check threw an exception: " + e.getMessage()));
                    }
                }
            }
        } else if (checkCRLEnabled) { 
             logger.info("CRL check for {} was enabled but skipped due to definitive OCSP status: {}", certId, detailsToUpdate.getRevocationStatus());
        } else {
             logger.info("CRL check is disabled for {}.", certId);
        }
        
        // Final status determination
        if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN) {
            if (!checkOCSPEnabled && !checkCRLEnabled) {
                detailsToUpdate.setRevocationStatus(RevocationStatus.NOT_CHECKED);
                detailsToUpdate.setFailureReason("Neither OCSP nor CRL checks were enabled.");
                logger.info("Revocation for {}: NOT_CHECKED (both OCSP and CRL disabled).", certId);
            } else {
                // If checks were enabled but result is still UNKNOWN, ensure a reason explains why.
                String finalFailureReason = detailsToUpdate.getFailureReason();
                if (finalFailureReason == null || finalFailureReason.trim().isEmpty()) {
                     finalFailureReason = "Revocation status could not be determined via enabled checks (OCSP/CRL).";
                }
                detailsToUpdate.setFailureReason(finalFailureReason); // Ensure it's set
                logger.warn("Revocation for {}: UNKNOWN. Reason: {}", certId, finalFailureReason);
            }
        } else { // GOOD or REVOKED
            logger.info("Final revocation status for {}: {}. Reason: {}", certId, detailsToUpdate.getRevocationStatus(), detailsToUpdate.getFailureReason() == null ? "N/A" : detailsToUpdate.getFailureReason());
        }
    }

    /**
     * Performs OCSP check for the given certificate.
     * Updates {@code detailsToUpdate} with the OCSP URL, status, and failure reasons.
     *
     * @param cert The certificate to check.
     * @param issuerCert The issuer certificate.
     * @param detailsToUpdate The object to update with results.
     */
    private void checkOCSP(X509Certificate cert, X509Certificate issuerCert, CertificateDetails detailsToUpdate) {
        String certId = "Cert Subject: " + cert.getSubjectX500Principal().getName() + ", Serial: " + cert.getSerialNumber();
        String ocspUrl = getOCSPUrl(cert);
        detailsToUpdate.setOcspResponderUrl(ocspUrl); 

        if (ocspUrl == null) {
            logger.info("No OCSP URL found in AIA for {}.", certId);
            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "No OCSP URL found in certificate AIA extension."));
            // Status remains UNKNOWN from checkRevocation or previous check
            return;
        }
        logger.info("Attempting OCSP check for {} using responder: {}", certId, ocspUrl);

        try {
            // 1. Create CertificateID
            // Used to identify the certificate in the OCSP request.
            DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
            X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
            X509CertificateHolder issuerCertHolder = new JcaX509CertificateHolder(issuerCert);
            CertificateID certificateID = new CertificateID(digestCalculatorProvider.get(CertificateID.HASH_SHA1), issuerCertHolder, certHolder.getSerialNumber());
            logger.debug("OCSP CertificateID created for {}.", certId);

            // 2. Construct OCSP Request
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(certificateID);
            // Can add nonce here: builder.setRequestExtensions(...)
            OCSPReq request = builder.build();
            logger.debug("OCSP request constructed for {}.", certId);

            // 3. Send Request and Process Response
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) new URL(ocspUrl).openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/ocsp-request");
                connection.setRequestProperty("Accept", "application/ocsp-response");
                connection.setDoOutput(true);
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);

                try (OutputStream os = connection.getOutputStream()) {
                    os.write(request.getEncoded());
                }
                logger.debug("OCSP request sent to {} for {}.", ocspUrl, certId);

                int responseCode = connection.getResponseCode();
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    logger.warn("OCSP request to {} for {} failed: HTTP {}", ocspUrl, certId, responseCode);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "OCSP request to " + ocspUrl + " failed: HTTP " + responseCode));
                    return;
                }
                logger.debug("OCSP response received from {} for {}. HTTP Status: {}", ocspUrl, certId, responseCode);

                try (InputStream is = connection.getInputStream()) {
                    OCSPResp ocspResponse = new OCSPResp(is.readAllBytes());
                    logger.debug("OCSP response status from {}: {} for {}.", ocspUrl, ocspResponse.getStatus(), certId);


                if (ocspResponse.getStatus() != OCSPResp.SUCCESSFUL) {
                    logger.warn("OCSP server at {} returned non-SUCCESSFUL status: {} for {}.", ocspUrl, ocspResponse.getStatus(), certId);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"OCSP response from " + ocspUrl + " status: " + ocspResponse.getStatus()));
                    return;
                }

                BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResponse.getResponseObject();
                if (basicResponse == null) {
                    logger.warn("BasicOCSPResp is null in OCSP response from {} for {}.", ocspUrl, certId);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"BasicOCSPResp was null in OCSP response from " + ocspUrl));
                    return;
                }

                // Verify OCSP Response Signature
                X509CertificateHolder signingCertHolder = null;
                ResponderID rid = basicResponse.getResponderId();
                X509CertificateHolder[] responderCerts = basicResponse.getCerts();

                if (responderCerts != null && responderCerts.length > 0) {
                    logger.debug("Found {} certificate(s) in OCSP response. Attempting to match ResponderID.", responderCerts.length);
                    ASN1Primitive ridPrimitive = rid.toASN1Primitive();
                    for (X509CertificateHolder certHolderFromResponse : responderCerts) {
                        if (ridPrimitive instanceof X500Name) { // ResponderID is by Name
                            X500Name responderName = X500Name.getInstance(ridPrimitive);
                            if (certHolderFromResponse.getSubject().equals(responderName)) {
                                signingCertHolder = certHolderFromResponse;
                                logger.debug("Matched OCSP responder by subject name: {}", responderName);
                                break;
                            }
                        } else if (ridPrimitive instanceof ASN1OctetString) { // ResponderID is by KeyHash
                            ASN1OctetString responderKeyHash = (ASN1OctetString) ridPrimitive;
                            try {
                                DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
                                DigestCalculator digestCalculator = dcp.get(CertificateID.HASH_SHA1); // OCSP key hashes are typically SHA-1
                                OutputStream outputStream = digestCalculator.getOutputStream();
                                outputStream.write(certHolderFromResponse.getSubjectPublicKeyInfo().getEncoded("DER")); // Key to hash
                                outputStream.close();
                                byte[] calculatedKeyHash = digestCalculator.getDigest();
                                if (Arrays.equals(responderKeyHash.getOctets(), calculatedKeyHash)) {
                                    signingCertHolder = certHolderFromResponse;
                                    logger.debug("Matched OCSP responder by subject public key hash.");
                                    break;
                                }
                            } catch (Exception e) {
                                logger.error("Error calculating hash for OCSP responder cert {}: {}", certHolderFromResponse.getSubject(), e.getMessage(), e);
                            }
                        }
                    }
                    if (signingCertHolder == null) {
                        logger.warn("Could not match ResponderID with any certificate in the OCSP response. Will try issuer certificate.");
                    }
                }

                if (signingCertHolder == null) { // If no cert from response matched or no certs in response
                    logger.debug("No specific signing cert found in OCSP response or no match. Using issuer certificate to verify OCSP signature.");
                    try {
                        signingCertHolder = new JcaX509CertificateHolder(issuerCert);
                    } catch (CertificateEncodingException e) {
                        logger.error("Failed to convert issuer certificate to X509CertificateHolder for OCSP signature check: {}", e.getMessage(), e);
                        detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                        detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "Failed to prepare issuer cert for OCSP signature validation: " + e.getMessage()));
                        return;
                    }
                }

                if (signingCertHolder != null) {
                    try {
                        if (!basicResponse.isSignatureValid(signingCertHolder)) {
                            logger.warn("OCSP response signature verification FAILED for {} using responder cert: {}", certId, signingCertHolder.getSubject());
                            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "OCSP response signature is invalid."));
                            return; // Do not trust this response
                        }
                        logger.info("OCSP response signature VERIFIED successfully for {} using responder cert: {}", certId, signingCertHolder.getSubject());
                    } catch (OCSPException | OperatorCreationException e) {
                        logger.error("Error during OCSP signature verification for {}: {}", certId, e.getMessage(), e);
                        detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                        detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "Error verifying OCSP response signature: " + e.getMessage()));
                        return; // Error during verification
                    }
                } else {
                    // This case should not be reached if issuerCert fallback is always attempted and succeeds in conversion.
                    // However, if issuerCert conversion itself failed and no certs in response, this could be hit.
                    logger.warn("No OCSP responder certificate (neither from response nor issuer) available to verify signature for {}.", certId);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "No OCSP responder certificate available to verify signature."));
                    return; // Cannot verify signature
                }

                boolean statusFound = false;
                for (SingleResp singleResponse : basicResponse.getResponses()) {
                    // Compare the CertificateID from the response with the one from our request
                    if (singleResponse.getCertID().equals(certificateID)) {
                        statusFound = true;
                        Object status = singleResponse.getCertStatus();
                        if (status == CertificateStatus.GOOD) {
                            detailsToUpdate.setRevocationStatus(RevocationStatus.GOOD);
                            detailsToUpdate.setFailureReason(null); // Clear previous failure reasons as status is definitively GOOD
                            logger.info("OCSP status for {}: GOOD (Responder: {})", certId, ocspUrl);
                        } else if (status instanceof RevokedStatus) {
                            detailsToUpdate.setRevocationStatus(RevocationStatus.REVOKED);
                            RevokedStatus revokedStatus = (RevokedStatus) status;
                            String revocationReason = revokedStatus.hasRevocationReason() ? " Reason: " + revokedStatus.getRevocationReason() : "";
                            logger.warn("OCSP status for {}: REVOKED (Responder: {}). Time: {}.{}", certId, ocspUrl, revokedStatus.getRevocationTime(), revocationReason);
                            detailsToUpdate.setFailureReason("Certificate REVOKED via OCSP from " + ocspUrl + ". Time: " + revokedStatus.getRevocationTime() + "." + revocationReason);
                        } else if (status instanceof UnknownStatus) {
                            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                            logger.warn("OCSP status for {}: UNKNOWN (Responder: {})", certId, ocspUrl);
                            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"OCSP status UNKNOWN from " + ocspUrl));
                        } else { // Should not happen with standard OCSP responses
                            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                            logger.warn("OCSP status for {}: UNHANDLED (Responder: {}). Status object: {}", certId, ocspUrl, status);
                            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"OCSP status unhandled from " + ocspUrl + ": " + (status != null ? status.getClass().getName() : "null")));
                        }
                        break; // Found status for our specific certID
                    }
                }
                if (!statusFound) {
                    logger.warn("OCSP response from {} did not contain status for the requested certificate: {}", ocspUrl, certId);
                    detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                    detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"OCSP response from " + ocspUrl + " did not contain status for the certificate."));
                }
            }
        } catch (Exception e) {
            logger.error("Exception during OCSP check process for {} (URL: {}): {}", certId, ocspUrl, e.getMessage(), e);
            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(),"Exception during OCSP check with " + ocspUrl + ": " + e.getMessage()));
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Performs CRL check for the given certificate.
     * Updates {@code detailsToUpdate} with CRL URLs, status, and failure reasons.
     *
     * @param cert The certificate to check.
     * @param issuerCert The issuer certificate, used to verify CRL signature.
     * @param detailsToUpdate The object to update with results.
     */
    private void checkCRL(X509Certificate cert, X509Certificate issuerCert, CertificateDetails detailsToUpdate) {
        String certId = "Cert Subject: " + cert.getSubjectX500Principal().getName() + ", Serial: " + cert.getSerialNumber();
        List<String> crlUrls = getCRLUrls(cert);
        detailsToUpdate.setCrlDistributionPoints(crlUrls); // Store all found URLs
        boolean oneCrlProcessedSuccessfully = false; 
        String accumulatedCrlFailureReasons = "";

        if (crlUrls.isEmpty()) {
            logger.info("No CRL URLs found in CDP for {}.", certId);
             if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN || detailsToUpdate.getRevocationStatus() == RevocationStatus.NOT_CHECKED) {
                 detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "No CRL URLs found in certificate CDP extension."));
            }
            return;
        }
        
        if (issuerCert == null) { // Should have been checked by caller, but defensive check
            logger.warn("Cannot verify CRL for {} without issuer certificate.", certId);
            detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
            detailsToUpdate.setFailureReason(appendFailureReason(detailsToUpdate.getFailureReason(), "CRL check skipped: issuer certificate not available."));
            return;
        }

        for (String crlUrl : crlUrls) {
            logger.info("Attempting CRL check for {} using CRL: {}", certId, crlUrl);
            HttpURLConnection connection = null;
            try {
                // 1. Download CRL
                connection = (HttpURLConnection) new URL(crlUrl).openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);

                int responseCode = connection.getResponseCode();
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    logger.warn("CRL request to {} for {} failed: HTTP {}", crlUrl, certId, responseCode);
                    accumulatedCrlFailureReasons = appendFailureReason(accumulatedCrlFailureReasons, "CRL " + crlUrl + " request failed: HTTP " + responseCode + ". ");
                    continue; // Try next CRL URL
                }
                logger.debug("CRL downloaded from {} for {}.", crlUrl, certId);

                X509CRL crl;
                try (InputStream is = connection.getInputStream()) {
                    // 2. Parse CRL
                    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
                    crl = (X509CRL) cf.generateCRL(is);
                }

                // 3. Verify CRL Signature using issuer's public key
                crl.verify(issuerCert.getPublicKey(), "BC");
                logger.debug("CRL signature verified for {} from URL: {}", certId, crlUrl);

                // 4. Check CRL Validity Period (thisUpdate, nextUpdate)
                java.util.Date currentDate = new java.util.Date();
                if (crl.getThisUpdate().after(currentDate) || (crl.getNextUpdate() != null && crl.getNextUpdate().before(currentDate))) {
                    logger.warn("CRL from {} for {} is not within its validity period. ThisUpdate: {}, NextUpdate: {}", crlUrl, certId, crl.getThisUpdate(), crl.getNextUpdate());
                    accumulatedCrlFailureReasons = appendFailureReason(accumulatedCrlFailureReasons, "CRL " + crlUrl + " is out of validity period (ThisUpdate: " + crl.getThisUpdate() + ", NextUpdate: " + crl.getNextUpdate() + "). ");
                    continue; // Try next CRL if this one is out of date
                }
                logger.debug("CRL from {} for {} is within its validity period.", crlUrl, certId);
                oneCrlProcessedSuccessfully = true; // Mark that at least one CRL was successfully processed (signature & time valid)

                // 5. Check if the certificate is listed on the CRL
                if (crl.isRevoked(cert)) {
                    detailsToUpdate.setRevocationStatus(RevocationStatus.REVOKED);
                    X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
                    String reason = "";
                    if (entry != null && entry.getRevocationReason() != null) {
                        reason = " Reason: " + entry.getRevocationReason().toString();
                    }
                    logger.warn("Certificate {} REVOKED per CRL {}.{}", certId, crlUrl, reason);
                    detailsToUpdate.setFailureReason("Certificate REVOKED per CRL: " + crlUrl + "." + reason);
                    return; // Definitive REVOKED status found.
                }
                logger.info("Certificate {} is NOT revoked according to CRL: {}", certId, crlUrl);
                // If not revoked by this valid CRL, and current status is still UNKNOWN or NOT_CHECKED, set to GOOD.
                if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN || detailsToUpdate.getRevocationStatus() == RevocationStatus.NOT_CHECKED) {
                    detailsToUpdate.setRevocationStatus(RevocationStatus.GOOD);
                    detailsToUpdate.setFailureReason(null); // Clear previous failure reasons as we found a good CRL status.
                }
                return; // Definitive GOOD status found from a valid CRL.

            } catch (Exception e) {
                logger.error("Exception during CRL processing for {} from URL {}: {}", certId, crlUrl, e.getMessage(), e);
                accumulatedCrlFailureReasons = appendFailureReason(accumulatedCrlFailureReasons, "CRL " + crlUrl + " processing error: " + e.getMessage() + ". ");
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        // After checking all URLs, if status is still UNKNOWN or NOT_CHECKED
        if (detailsToUpdate.getRevocationStatus() == RevocationStatus.UNKNOWN || detailsToUpdate.getRevocationStatus() == RevocationStatus.NOT_CHECKED) {
            String existingFailureReason = detailsToUpdate.getFailureReason();
            if (!oneCrlProcessedSuccessfully && !crlUrls.isEmpty()) { // All CRLs failed to process (network, parse, verify signature/time)
                detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN);
                detailsToUpdate.setFailureReason(appendFailureReason(existingFailureReason, "All CRLs failed to process. Reasons: " + accumulatedCrlFailureReasons));
            } else if (oneCrlProcessedSuccessfully) { 
                // This case should not be reached if a CRL was successfully processed and the cert was not on it,
                // as the status should have been set to GOOD and returned.
                // If it is reached, it implies an unexpected logic flow or that 'GOOD' was overwritten.
                detailsToUpdate.setRevocationStatus(RevocationStatus.UNKNOWN); 
                detailsToUpdate.setFailureReason(appendFailureReason(existingFailureReason, "CRL checks completed, but status remains UNKNOWN despite processing some CRLs. Check logs. Errors: " + accumulatedCrlFailureReasons));
            } else if (crlUrls.isEmpty()) {
                // This case is handled at the start of the method. If failureReason is still null, it means OCSP was also not helpful.
                if (existingFailureReason == null || existingFailureReason.trim().isEmpty()) {
                     detailsToUpdate.setFailureReason("No CRL URLs found and OCSP did not yield a definitive status.");
                }
            }
        }
    }
    
    /**
     * Appends a new failure reason to an existing one, handling nulls and avoiding duplicates.
     *
     * @param existingReason The existing failure reason string (can be null or empty).
     * @param newReason      The new failure reason to append.
     * @return A combined failure reason string.
     */
    private String appendFailureReason(String existingReason, String newReason) {
        if (newReason == null || newReason.trim().isEmpty()) return existingReason;
        if (existingReason == null || existingReason.trim().isEmpty()) {
            return newReason;
        }
        // Avoid duplicate messages if newReason is already part of existingReason
        if (existingReason.contains(newReason)) return existingReason;
        return existingReason + "; " + newReason;
    }

/**
 * Extracts the OCSP responder URL from the Authority Information Access (AIA)
 * extension of an X.509 certificate.
 *
 * @param cert The certificate from which to extract the OCSP URL.
 * @return The OCSP responder URL as a String, or null if not found or an error occurs.
 */
private String getOCSPUrl(X509Certificate cert) {
    String certId = "Cert Subject: " + cert.getSubjectX500Principal().getName() + ", Serial: " + cert.getSerialNumber();
    logger.debug("Extracting OCSP URL for {}.", certId);
    // Standard OID for Authority Information Access extension
    byte[] aiaBytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
    if (aiaBytes == null) {
        logger.info("No AIA extension found in certificate {}.", certId);
        return null;
    }
    try (ASN1InputStream asn1In = new ASN1InputStream(aiaBytes)) {
        // The extension value is OCTET STRING, get the octets
        ASN1OctetString octetString = (ASN1OctetString) asn1In.readObject();
        if (octetString == null) {
            logger.warn("AIA extension octet string is null for {}.", certId);
            return null; 
        }

        try (ASN1InputStream aiaSeqIn = new ASN1InputStream(octetString.getOctets())) {
            ASN1Primitive aiaPrimitive = aiaSeqIn.readObject();
            // The AIA extension is a sequence of AccessDescription objects
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaPrimitive);

            for (AccessDescription ad : aia.getAccessDescriptions()) {
                // Look for OCSP access method (id_ad_ocsp)
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName location = ad.getAccessLocation();
                    // Check if the location is a URI
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = ((DERIA5String) location.getName()).getString();
                        if (url.startsWith("http://") || url.startsWith("https://")) {
                            logger.info("Found OCSP URL for {}: {}", certId, url);
                            return url;
                        } else {
                            logger.warn("Found OCSP access location for {} but not a valid HTTP/HTTPS URL: {}", certId, url);
                        }
                    } else {
                        logger.warn("Found OCSP access location for {} but not a URI: TagNo {}", certId, location.getTagNo());
                    }
                }
            }
        }
    } catch (IOException | IllegalArgumentException e) { 
        logger.error("Error parsing AIA extension for OCSP URL in {}: {}", certId, e.getMessage(), e);
    }
    logger.info("No valid OCSP URL found after parsing AIA for {}.", certId);
    return null;
}


/**
 * Extracts CRL distribution point URLs from the CRL Distribution Points (CDP)
 * extension of an X.509 certificate.
 *
 * @param cert The certificate from which to extract CRL URLs.
 * @return A list of CRL distribution point URLs (Strings). Returns an empty list if none are found or an error occurs.
 */
private List<String> getCRLUrls(X509Certificate cert) {
    String certId = "Cert Subject: " + cert.getSubjectX500Principal().getName() + ", Serial: " + cert.getSerialNumber();
    logger.debug("Extracting CRL URLs for {}.", certId);
    List<String> urls = new ArrayList<>();
    // Standard OID for CRL Distribution Points extension
    byte[] crlDpBytes = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
    if (crlDpBytes == null) {
        logger.info("No CRL Distribution Points extension found in certificate {}.", certId);
        return urls;
    }

    try (ASN1InputStream asn1In = new ASN1InputStream(new ByteArrayInputStream(crlDpBytes))) {
        // The extension value is OCTET STRING, get the octets
        DEROctetString dos = (DEROctetString) asn1In.readObject();
        if (dos == null) {
             logger.warn("CRL DP extension octet string is null for {}.", certId);
            return urls;
        }

        try (ASN1InputStream crlDistSeqIn = new ASN1InputStream(new ByteArrayInputStream(dos.getOctets()))) {
            // The CRLDistPoint is a sequence of DistributionPoint objects
            CRLDistPoint distPoint = CRLDistPoint.getInstance(crlDistSeqIn.readObject());

            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                // Check if the DistributionPointName contains GeneralNames
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames gns = (GeneralNames) dpn.getName();
                    for (GeneralName gn : gns.getNames()) {
                        // Look for URIs
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = ((DERIA5String) gn.getName()).getString();
                            if (url.startsWith("http://") || url.startsWith("https://")) {
                                urls.add(url);
                                logger.info("Found CRL URL for {}: {}", certId, url);
                            } else {
                                logger.warn("Found CRL distribution point for {} but not a valid HTTP/HTTPS URL: {}", certId, url);
                            }
                        }
                    }
                }
            }
        }
    } catch (Exception e) { 
        logger.error("Error parsing CRL Distribution Points extension for {}: {}", certId, e.getMessage(), e);
    }
    if (urls.isEmpty()) {
        logger.info("No valid CRL URLs found after parsing CDP for {}.", certId);
    }
    return urls;
}
    // Old verifyOCSPResponse and parseCRL methods can be removed or adapted if Bouncy Castle handles parsing.
    // For now, Bouncy Castle's OCSPResp and standard CertificateFactory for CRL parsing are used.
}