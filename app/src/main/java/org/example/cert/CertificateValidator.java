package org.example.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.example.model.CertificateDetails;
import org.example.model.RevocationStatus;
import org.example.model.TrustStatus;
import org.example.config.SSLTestConfig; // Ensure this import is present

/**
 * Validates an X.509 certificate chain against a truststore and performs revocation checks.
 * This class uses a {@link CertificateRevocationChecker} to determine OCSP/CRL status
 * and a system or custom {@link javax.net.ssl.X509TrustManager} for path validation.
 * It also provides methods for hostname verification against a certificate.
 */
public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    /** 
     * Formatter for date output. 
     * Note: While defined, it's not directly used in Javadoc examples for brevity but provides context for date handling.
     */
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    /** 
     * Cache for storing results of validated certificate chains. 
     * The key is generated from the first certificate in the chain (end-entity).
     * This helps avoid redundant, potentially time-consuming validation for the same chain.
     */
    private static final Map<String, List<CertificateDetails>> CERTIFICATE_CACHE = new ConcurrentHashMap<>();

    /** The custom keystore file, if provided by the user for custom trust anchors. Null if system default is used. */
    private final File keystoreFile;
    /** The password for the custom keystore file. Null if no password or no custom keystore. */
    private final String keystorePassword;
    /** The checker responsible for OCSP and CRL lookups for individual certificates in the chain. */
    private final CertificateRevocationChecker revocationChecker;

    /**
     * Constructs a CertificateValidator with specified truststore settings and revocation check configuration.
     *
     * @param keystoreFile      A custom JKS or PKCS12 keystore file to use for establishing trust.
     *                          If null, the system's default truststore will be used.
     * @param keystorePassword  The password for the custom keystore. May be null if the keystore
     *                          does not require a password or if {@code keystoreFile} is null.
     * @param config            The {@link SSLTestConfig} object, which might be used for other configurations or logging.
     * @param revocationChecker An instance of {@link CertificateRevocationChecker} for performing OCSP/CRL checks.
     */
    public CertificateValidator(File keystoreFile, String keystorePassword, SSLTestConfig config, CertificateRevocationChecker revocationChecker) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
        this.revocationChecker = revocationChecker; // Use the injected instance

        if (revocationChecker == null) {
            // This case should ideally be prevented by the caller, but as a safeguard:
            logger.error("CertificateRevocationChecker instance is null in CertificateValidator constructor. Revocation checks will not be performed correctly.");
            // Depending on desired strictness, could throw IllegalArgumentException here.
            // For now, logging an error and continuing; behavior of revocationChecker.checkRevocation will be NPE if not handled.
        }
        
        // Logging related to config can remain if config is used for other things.
        // If config is only for revocation settings, this log might need adjustment or could be removed if config is removed.
        logger.info("CertificateValidator initialized. Custom keystore: {}. Revocation checker has been provided.", 
                    keystoreFile != null ? keystoreFile.getAbsolutePath() : "Using System Default");
    }

    /**
     * Performs a basic check of the system's current time, specifically the year,
     * to detect potentially gross inaccuracies that could interfere with certificate
     * date validity (notBefore/notAfter) assessments.
     * Logs a warning if the system year seems to be outside a plausible range.
     */
    public void checkSystemTime() {
        try {
            Calendar cal = Calendar.getInstance();
            int currentYear = cal.get(Calendar.YEAR);
            // Define a plausible year range. Example: current year +/- a small delta, or a fixed recent range.
            int minAcceptableYear = 2023; // Or Calendar.getInstance().get(Calendar.YEAR) - 1;
            int maxAcceptableYear = Calendar.getInstance().get(Calendar.YEAR) + 1; // Allow current year and next, for example.
            
            if (currentYear < minAcceptableYear || currentYear > maxAcceptableYear) {
                logger.warn("⚠️ System time might be inaccurate! Current system year: {}. This can cause certificate validation issues (notBefore/notAfter). Please ensure system time is synchronized.", currentYear);
            } else {
                logger.debug("System time check: Current year {} is within acceptable range ({}-{}).", currentYear, minAcceptableYear, maxAcceptableYear);
            }
        } catch (Exception e) {
            logger.error("Error occurred during system time check: {}", e.getMessage(), e);
        }
    }

    /**
     * Validates the given certificate chain. This includes:
     * <ol>
     *   <li>Conversion of {@code Certificate[]} to {@code X509Certificate[]}.</li>
     *   <li>A preliminary check of the system time for gross inaccuracies.</li>
     *   <li>Checking a cache for previously validated results for this chain.</li>
     *   <li>If not cached, initialization of TrustManager (system default or custom keystore).</li>
     *   <li>Validation of the chain against the TrustManager (path validation).</li>
     *   <li>Population of {@link CertificateDetails} for each certificate in the chain with its properties.</li>
     *   <li>Performing revocation checks (OCSP/CRL, if enabled) for each certificate, updating its {@code CertificateDetails}.</li>
     *   <li>If any certificate is found to be REVOKED, the entire chain is marked as NOT_TRUSTED and a {@link CertificateException} is thrown.</li>
     *   <li>If all checks pass, the result is cached and returned.</li>
     * </ol>
     *
     * @param certs The certificate chain to validate, ordered from the end-entity certificate to an intermediate/root CA.
     * @return A list of {@link CertificateDetails} objects, each corresponding to a certificate in the input chain,
     *         populated with detailed validation information.
     * @throws CertificateException If the certificate chain is invalid due to trust issues, revocation, expiry, or other reasons.
     */
    public List<CertificateDetails> validateCertificateChain(Certificate[] certs) throws CertificateException {
        if (certs == null || certs.length == 0) {
            logger.error("Certificate chain validation attempt with no certificates provided.");
            throw new CertificateException("No certificates provided for validation.");
        }

        X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
        String firstCertSubject = x509Certs[0].getSubjectX500Principal().getName();
        logger.info("Starting certificate chain validation for chain starting with: {}", firstCertSubject);

        // Check system time for gross inaccuracies that might affect date-based validity checks
        checkSystemTime();

        // Check cache for existing validation result to avoid re-computation
        // The cache key is generated using the serial number and issuer DN of the end-entity certificate.
        String certKey = x509Certs[0].getSerialNumber().toString(16) + "_" + x509Certs[0].getIssuerX500Principal().getName();
        List<CertificateDetails> cachedResult = CERTIFICATE_CACHE.get(certKey);
        if (cachedResult != null) {
            logger.info("Certificate chain for {} found in cache.", firstCertSubject);
            // Ensure cached result reflects final status (e.g., if a cached entry was for a revoked cert or untrusted chain)
            for (CertificateDetails detail : cachedResult) {
                if (detail.getRevocationStatus() == RevocationStatus.REVOKED) {
                    logger.warn("Cached chain for {} contains a revoked certificate ({}). Failing validation from cache.", firstCertSubject, detail.getSubjectDN());
                    throw new CertificateException("Certificate chain is invalid: certificate " + detail.getSubjectDN() + " (Serial: " + detail.getSerialNumber() + ") is REVOKED. Reason: " + detail.getFailureReason());
                }
                if (detail.getTrustStatus() == TrustStatus.NOT_TRUSTED) {
                     logger.warn("Cached chain for {} is marked NOT_TRUSTED. Failing validation from cache. Reason: {}", firstCertSubject, detail.getFailureReason());
                    throw new CertificateException("Certificate chain is invalid: " + (detail.getFailureReason() != null ? detail.getFailureReason() : "General trust failure from cache."));
                }
            }
            return cachedResult;
        }
        logger.debug("Certificate chain for {} not found in cache. Proceeding with full validation.", firstCertSubject);

        List<CertificateDetails> certificateDetailsList = new ArrayList<>();
        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);
        // Determine authentication type based on the end-entity certificate's signature algorithm for checkServerTrusted
        String auth = determineAuthType(x509Certs[0].getSigAlgName());

        // Main validation block: try-catch handles fundamental trust issues or revocation failures.
        try {
            // Step 1: Initial chain trust validation by the system's or custom TrustManager.
            // This method throws a CertificateException if the chain is not trusted.
            logger.debug("Performing TrustManager.checkServerTrusted for chain starting with {}.", firstCertSubject);
            tm.checkServerTrusted(x509Certs, auth);
            logger.info("TrustManager.checkServerTrusted for chain starting with {} was successful.", firstCertSubject);

            // Determine the trust basis if the TrustManager check passed.
            TrustStatus determinedTrustStatus = (keystoreFile != null) ? TrustStatus.TRUSTED_BY_CUSTOM_KEYSTORE : TrustStatus.TRUSTED_BY_ROOT;

            // Populate initial details for each certificate after successful TrustManager check.
            // This includes basic properties, validity dates, and initial trust status.
            for (X509Certificate cert : x509Certs) {
                CertificateDetails details = new CertificateDetails();
                details.setSubjectDN(cert.getSubjectX500Principal().getName());
                details.setIssuerDN(cert.getIssuerX500Principal().getName());
                details.setVersion(cert.getVersion());
                details.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());
                details.setValidFrom(cert.getNotBefore());
                details.setValidUntil(cert.getNotAfter());
                details.setSignatureAlgorithm(cert.getSigAlgName());
                details.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
                try {
                    var sans = cert.getSubjectAlternativeNames(); // Collection<List<?>>
                    if (sans != null) {
                        Map<String, List<String>> sanMap = new HashMap<>();
                        for (List<?> sanEntry : sans) { // Each entry is a List [Integer type, String value]
                            if (sanEntry.size() == 2) { // Ensure the entry is a pair
                                Integer type = (Integer) sanEntry.get(0);
                                String value = (String) sanEntry.get(1);
                                List<String> sansForType = sanMap.computeIfAbsent(type.toString(), k -> new ArrayList<>());
                                sansForType.add(value);
                            }
                        }
                        details.setSubjectAlternativeNames(sanMap);
                    }
                } catch (java.security.cert.CertificateParsingException e) { // More specific exception type
                    logger.warn("Failed to parse Subject Alternative Names for cert {}: {}", cert.getSubjectX500Principal(), e.getMessage());
                    details.setFailureReason((details.getFailureReason() == null ? "" : details.getFailureReason() + "; ") + "Error parsing SANs: " + e.getMessage());
                }
                details.setSelfSigned(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
                details.setExpired(cert.getNotAfter().before(new Date())); // Check against current time
                details.setNotYetValid(cert.getNotBefore().after(new Date())); // Check against current time
                details.setTrustStatus(determinedTrustStatus);
                details.setRevocationStatus(RevocationStatus.NOT_CHECKED); // Initial status before specific checks
                certificateDetailsList.add(details);
            }

            // Step 2: Perform revocation checks for each certificate in the chain.
            logger.info("Initiating revocation checks for {} certificates in the chain starting with {}.", x509Certs.length, firstCertSubject);
            for (int i = 0; i < x509Certs.length; i++) {
                X509Certificate currentCert = x509Certs[i];
                CertificateDetails currentDetails = certificateDetailsList.get(i);
                String currentCertId = "Cert Subject: " + currentDetails.getSubjectDN() + ", Serial: " + currentDetails.getSerialNumber();
                logger.debug("Performing revocation check for {}.", currentCertId);

                X509Certificate issuerCert = null;
                // Determine the issuer certificate for the current certificate.
                // For self-signed certs (typically root), it's the cert itself.
                // Otherwise, try to find it in the provided chain.
                if (currentDetails.isSelfSigned()) {
                    issuerCert = currentCert; 
                    logger.debug("Certificate {} is self-signed, using itself as issuer for revocation check.", currentCertId);
                } else {
                    // Attempt to find the issuer by looking at the next cert in the chain (if ordered)
                    // or by matching Subject/Issuer DNs across the chain for robustness.
                    if (i + 1 < x509Certs.length && currentCert.getIssuerX500Principal().equals(x509Certs[i+1].getSubjectX500Principal())) {
                        issuerCert = x509Certs[i+1];
                        logger.debug("Issuer for {} found as next in chain: {}", currentCertId, x509Certs[i+1].getSubjectX500Principal().getName());
                    } else { // Fallback: search the entire chain if not immediately next (e.g. unordered chain)
                        for (X509Certificate potentialIssuer : x509Certs) {
                            if (currentCert.getIssuerX500Principal().equals(potentialIssuer.getSubjectX500Principal()) && !currentCert.equals(potentialIssuer)) {
                                issuerCert = potentialIssuer;
                                logger.debug("Issuer for {} found by DN match in chain: {}", currentCertId, potentialIssuer.getSubjectX500Principal().getName());
                                break;
                            }
                        }
                    }
                }

                if (issuerCert == null && !currentDetails.isSelfSigned()) {
                     logger.warn("Issuer certificate not found in provided chain for non-self-signed certificate {}. Revocation check might be incomplete.", currentCertId);
                     currentDetails.setRevocationStatus(RevocationStatus.UNKNOWN);
                     currentDetails.setFailureReason((currentDetails.getFailureReason() == null ? "" : currentDetails.getFailureReason() + "; ") + "Issuer certificate not found in chain for revocation check.");
                }
                
                // Perform the actual revocation check (OCSP/CRL) using the determined issuer.
                // The revocationChecker will update currentDetails with status and failure reasons.
                revocationChecker.checkRevocation(currentCert, issuerCert, currentDetails);
                logger.debug("Revocation check completed for {}. Status: {}, Reason: {}", currentCertId, currentDetails.getRevocationStatus(), currentDetails.getFailureReason());

                // If any certificate is found REVOKED, the entire chain's trust is compromised.
                if (currentDetails.getRevocationStatus() == RevocationStatus.REVOKED) {
                    logger.error("Certificate {} is REVOKED. Failing chain validation. Reason: {}", currentCertId, currentDetails.getFailureReason());
                    // Update trust status for all certificates in this chain to NOT_TRUSTED.
                    for (CertificateDetails detail : certificateDetailsList) {
                        detail.setTrustStatus(TrustStatus.NOT_TRUSTED);
                        // Append a general chain failure reason if no specific one is already there or if it's different
                        // from the reason on the certificate that was actually found to be revoked.
                        if (detail != currentDetails) { 
                           String existingFailReason = detail.getFailureReason();
                           String revokedMsg = "Chain invalid due to revoked certificate: " + currentDetails.getSubjectDN();
                           detail.setFailureReason(existingFailReason == null || existingFailReason.isEmpty() ? revokedMsg : existingFailReason + "; " + revokedMsg);
                        }
                    }
                    // Throw an exception to signal overall chain validation failure.
                    throw new CertificateException("Certificate chain is invalid: certificate " + currentDetails.getSubjectDN() + " (Serial: " + currentDetails.getSerialNumber() + ") is REVOKED. Reason: " + currentDetails.getFailureReason());
                }
            }
            
            // If all checks passed (no exceptions thrown from TrustManager or due to revocation)
            logger.info("All trust and revocation checks passed for chain starting with {}.", firstCertSubject);
            logger.info("Storing validation results for chain {} in cache.", firstCertSubject);
            CERTIFICATE_CACHE.put(certKey, certificateDetailsList);
            return certificateDetailsList;

        } catch (CertificateException e) { // Catches exceptions from tm.checkServerTrusted OR the explicit throw for REVOKED status
            logger.warn("Certificate chain validation failed for chain starting with {}. Reason: {}", firstCertSubject, e.getMessage());
            
            // If certificateDetailsList is empty, it means tm.checkServerTrusted likely failed before individual details were populated.
            // Populate it now to ensure all certificates in the original chain are marked as NOT_TRUSTED.
            if (certificateDetailsList.isEmpty()) {
                 logger.debug("Populating certificateDetailsList in main catch block as it was empty for chain: {}", firstCertSubject);
                 for (X509Certificate cert : x509Certs) {
                    CertificateDetails details = new CertificateDetails();
                    details.setSubjectDN(cert.getSubjectX500Principal().getName());
                    details.setIssuerDN(cert.getIssuerX500Principal().getName());
                    details.setVersion(cert.getVersion());
                    details.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());
                    details.setValidFrom(cert.getNotBefore());
                    details.setValidUntil(cert.getNotAfter());
                    details.setSignatureAlgorithm(cert.getSigAlgName());
                    details.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
                     try {
                        var sans = cert.getSubjectAlternativeNames();
                        if (sans != null) {
                            Map<String, List<String>> sanMap = new HashMap<>();
                            for (var sanItem : sans) { // Corrected variable name from san to sanItem
                                Integer type = (Integer) sanItem.get(0);
                                String value = (String) sanItem.get(1);
                                List<String> sansForType = sanMap.computeIfAbsent(type.toString(), k -> new ArrayList<>());
                                sansForType.add(value);
                            }
                            details.setSubjectAlternativeNames(sanMap);
                        }
                    } catch (java.security.cert.CertificateParsingException sanEx) { // More specific exception type
                        logger.warn("Failed to parse Subject Alternative Names for cert {} during error handling: {}", cert.getSubjectX500Principal(), sanEx.getMessage());
                    }
                    details.setSelfSigned(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
                    details.setExpired(cert.getNotAfter().before(new Date()));
                    details.setNotYetValid(cert.getNotBefore().after(new Date()));
                    details.setTrustStatus(TrustStatus.NOT_TRUSTED);
                    details.setRevocationStatus(RevocationStatus.NOT_CHECKED); // Revocation checks might not have run or completed
                    details.setFailureReason(e.getMessage()); // Set the primary failure reason from the caught exception
                    certificateDetailsList.add(details);
                 }
            } else {
                // If the list was already populated (e.g., TrustManager check passed but revocation check failed),
                // ensure all certificates reflect the NOT_TRUSTED status.
                for (CertificateDetails detail : certificateDetailsList) {
                    // Only update if not already marked NOT_TRUSTED by a more specific revocation failure.
                    if (detail.getTrustStatus() != TrustStatus.NOT_TRUSTED) { 
                        detail.setTrustStatus(TrustStatus.NOT_TRUSTED);
                        // Append the general failure reason if no specific one (like REVOKED) is already dominant.
                        String existingReason = detail.getFailureReason();
                        detail.setFailureReason(existingReason == null || existingReason.isEmpty() ? e.getMessage() : existingReason + "; " + e.getMessage());
                    }
                }
            }
            // Do not cache this result as trusted because an exception occurred.
            logger.warn("Chain validation failed for {}, not caching as trusted.", firstCertSubject);
            throw e; // Re-throw the original (or revocation-specific) exception
        }
    }

    // The getCertificateKey method was removed as its logic is now inlined at the call site within validateCertificateChain.
    // This was done to remove an unused method that also contained duplicated (and incorrect) code fragments from another part of the class.

    private TrustManagerFactory initializeTrustManagerFactory() throws CertificateException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if (keystoreFile != null) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(keystoreFile.toURI().toURL().openStream(),
                        keystorePassword != null ? keystorePassword.toCharArray() : null);
                tmf.init(ks);
                logger.info("Custom keystore loaded for TrustManager.");
            } else {
                tmf.init((KeyStore) null); // Uses default system truststore
                logger.info("Default system truststore used for TrustManager.");
            }
            return tmf;
        } catch (Exception e) {
            throw new CertificateException("Failed to initialize trust manager: " + e.getMessage(), e);
        }
    }

    private X509TrustManager findX509TrustManager(TrustManagerFactory tmf) throws CertificateException {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new CertificateException("No X509TrustManager found");
    }

    private String determineAuthType(String sigAlg) {
        // 简化认证类型判断
        return sigAlg.toUpperCase().contains("ECDSA") ? "ECDHE_ECDSA" : 
               sigAlg.toUpperCase().contains("RSA") ? "RSA" : sigAlg;
    }

    // getCertificateInfo method is removed as its functionality is merged into validateCertificateChain

    public boolean verifyHostname(X509Certificate cert, String hostname) {
        try {
            if (hostname == null) {
                return false;
            }

            logger.debug("Verifying hostname: {}", hostname);

            // 标准化主机名 (处理国际化域名)
            String normalizedHostname = normalizeHostname(hostname);
            logger.debug("Normalized hostname: {}", normalizedHostname);

            // 检查主机名是否为IP地址
            boolean isIpAddress = isIpAddress(normalizedHostname);
            logger.debug("Is IP address: {}", isIpAddress);

            // 首先检查SubjectAlternativeNames
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                logger.debug("Certificate contains {} SAN entries", sans.size());
                for (var san : sans) {
                    Integer type = (Integer) san.get(0);
                    String value = (String) san.get(1);
                    logger.debug("SAN entry: type={}, value={}", type, value);

                    // DNS类型 = 2
                    if (type == 2 && !isIpAddress) {
                        String normalizedValue = normalizeHostname(value);
                        logger.debug("Normalized SAN value: {}", normalizedValue);
                        logger.debug("Comparing: {} vs {}", normalizedValue, normalizedHostname);

                        if (normalizedValue.equals(normalizedHostname)) {
                            logger.debug("Direct match found!");
                            logger.debug("Hostname {} matched with SAN DNS: {}", normalizedHostname, value);
                            return true;
                        } else if (matchesHostname(normalizedValue, normalizedHostname)) {
                            logger.debug("Wildcard match found!");
                            logger.debug("Hostname {} matched with SAN DNS (wildcard): {}", normalizedHostname, value);
                            return true;
                        }
                    }
                    // IP类型 = 7
                    else if (type == 7 && isIpAddress) {
                        if (value.equals(normalizedHostname)) {
                            logger.debug("IP address {} matched with SAN IP: {}", normalizedHostname, value);
                            return true;
                        }
                    }
                }
            }

            // 如果是IP地址但没有匹配的SAN IP项，则失败
            if (isIpAddress) {
                return false;
            }

            // 回退到Subject DN中的Common Name (CN)
            // 注意：这仅为了兼容性，现代证书应使用SAN
            String subjectDN = cert.getSubjectX500Principal().getName();
            String[] parts = subjectDN.split(",");
            for (String part : parts) {
                if (part.trim().startsWith("CN=")) {
                    String cn = part.substring(3).trim();
                    if (matchesHostname(cn, normalizedHostname)) {
                        logger.debug("Hostname {} matched with CN: {}", normalizedHostname, cn);
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            logger.error("Hostname verification error: {}", e.getMessage(), e);
            return false;
        }
    }

    private String normalizeHostname(String hostname) {
        if (hostname == null) {
            return null;
        }

        // 首先转为小写
        hostname = hostname.toLowerCase();

        // 去除尾部的点（如 "example.com."）
        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }

        // 处理国际化域名 - 统一转换为Punycode格式
        try {
            // 确保总是转换为Punycode，不管输入形式如何
            // 这样可以确保一致的比较，无论是Unicode还是已经是Punycode格式
            String asciiForm = IDN.toASCII(hostname);

            // 如果转换结果不同，则使用ASCII格式
            if (!asciiForm.equals(hostname)) {
                logger.debug("IDN conversion: {} -> {}", hostname, asciiForm);
            }
            return asciiForm;

        } catch (Exception e) {
            logger.error("IDN conversion failed: {}, error: {}", hostname, e.getMessage());
            // 如果转换失败，返回原始域名
            return hostname;
        }
    }

    private boolean isIpAddress(String hostname) {
        try {
            // 尝试解析为InetAddress，如果成功且不是包含非IP信息的主机名，则为IP地址
            InetAddress addr = InetAddress.getByName(hostname);
            return addr.getHostAddress().equals(hostname);
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private boolean matchesHostname(String pattern, String hostname) {
        // 标准化模式和主机名
        pattern = normalizeHostname(pattern);

        // 直接匹配
        if (pattern.equals(hostname)) {
            return true;
        }

        // 通配符匹配逻辑
        if (pattern.startsWith("*.")) {
            // 通配符只能在最左边的部分
            if (pattern.indexOf('*', 1) != -1) {
                return false;
            }

            // 提取通配符后的部分
            String suffix = pattern.substring(1); // 得到 ".example.com"

            // 验证主机名是否包含足够的部分
            int dots = countDots(hostname);
            if (dots < 1) {
                return false; // 需要至少一个点才能匹配通配符
            }

            // 检查主机名是否以模式后缀结尾
            if (!hostname.endsWith(suffix)) {
                return false;
            }

            // 确保通配符只匹配到下一个点之前的部分
            String prefix = hostname.substring(0, hostname.length() - suffix.length());
            if (prefix.contains(".")) {
                return false; // 不允许通配符跨越多个域级别
            }

            // 通过所有检查
            return true;
        }

        return false;
    }

    private int countDots(String s) {
        return (int) s.chars().filter(c -> c == '.').count();
    }
}
