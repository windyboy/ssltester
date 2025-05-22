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

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final Map<String, List<CertificateDetails>> CERTIFICATE_CACHE = new ConcurrentHashMap<>();

import org.example.config.SSLTestConfig;

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final Map<String, List<CertificateDetails>> CERTIFICATE_CACHE = new ConcurrentHashMap<>();

    private final File keystoreFile;
    private final String keystorePassword;
    private final CertificateRevocationChecker revocationChecker;

    public CertificateValidator(File keystoreFile, String keystorePassword, SSLTestConfig config) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
        if (config == null) {
            logger.warn("SSLTestConfig is null, defaulting OCSP to true and CRL to false for CertificateRevocationChecker.");
            this.revocationChecker = new CertificateRevocationChecker(true, false);
        } else {
            this.revocationChecker = new CertificateRevocationChecker(config.isCheckOCSP(), config.isCheckCRL());
            logger.info("CertificateRevocationChecker initialized with OCSP: {}, CRL: {}", config.isCheckOCSP(), config.isCheckCRL());
        }
    }

    /**
     * 检查系统时间是否可能不准确
     * 主要检查年份是否在合理范围内，因为证书验证对时间非常敏感
     */
    public void checkSystemTime() {
        try {
            Calendar cal = Calendar.getInstance();
            int currentYear = cal.get(Calendar.YEAR);
            
            // 检查年份
            if (currentYear < 2023 || currentYear > 2024) {
                logger.warn("⚠️ 系统时间可能不准确！当前年份: {}，这会导致证书验证问题", currentYear);
                logger.warn("请同步您的系统时间以确保证书验证正确");
            }
        } catch (Exception e) {
            logger.error("检查系统时间时发生错误", e);
        }
    }

    public List<CertificateDetails> validateCertificateChain(Certificate[] certs) throws CertificateException {
        if (certs == null || certs.length == 0) {
            logger.error("Certificate chain validation attempt with no certificates provided.");
            throw new CertificateException("No certificates provided for validation.");
        }

        X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
        String firstCertSubject = x509Certs[0].getSubjectX500Principal().getName();
        logger.info("Starting certificate chain validation for chain starting with: {}", firstCertSubject);

        // Check system time for gross inaccuracies
        checkSystemTime();

        // Check cache
        String certKey = getCertificateKey(x509Certs[0]);
        List<CertificateDetails> cachedResult = CERTIFICATE_CACHE.get(certKey);
        if (cachedResult != null) {
            logger.info("Certificate chain for {} found in cache.", firstCertSubject);
            // Check if any cached cert was marked as revoked; if so, re-throw to ensure failure.
            for (CertificateDetails detail : cachedResult) {
                if (detail.getRevocationStatus() == RevocationStatus.REVOKED) {
                    logger.warn("Cached chain for {} contains a revoked certificate ({}). Failing validation.", firstCertSubject, detail.getSubjectDN());
                    throw new CertificateException("Certificate chain is invalid: certificate " + detail.getSubjectDN() + " (Serial: " + detail.getSerialNumber() + ") is REVOKED. Reason: " + detail.getFailureReason());
                }
                if (detail.getTrustStatus() == TrustStatus.NOT_TRUSTED) {
                     logger.warn("Cached chain for {} is marked NOT_TRUSTED. Failing validation. Reason: {}", firstCertSubject, detail.getFailureReason());
                    throw new CertificateException("Certificate chain is invalid: " + (detail.getFailureReason() != null ? detail.getFailureReason() : "General trust failure from cache."));
                }
            }
            return cachedResult;
        }
        logger.debug("Certificate chain for {} not found in cache. Proceeding with full validation.", firstCertSubject);

        List<CertificateDetails> certificateDetailsList = new ArrayList<>();
        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);
        String auth = determineAuthType(x509Certs[0].getSigAlgName());

        try {
            // Step 1: Initial chain trust validation by the TrustManager
            logger.debug("Performing TrustManager.checkServerTrusted for chain starting with {}.", firstCertSubject);
            tm.checkServerTrusted(x509Certs, auth);
            logger.info("TrustManager.checkServerTrusted for chain starting with {} was successful.", firstCertSubject);

            TrustStatus determinedTrustStatus = (keystoreFile != null) ? TrustStatus.TRUSTED_BY_CUSTOM_KEYSTORE : TrustStatus.TRUSTED_BY_ROOT;

            // Populate initial details after successful TrustManager check
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
                        Map<String, String> sanMap = new HashMap<>();
                        for (var san : sans) {
                            Integer type = (Integer) san.get(0);
                            String value = (String) san.get(1);
                            sanMap.put(type.toString(), value);
                        }
                        details.setSubjectAlternativeNames(sanMap);
                    }
                } catch (CertificateParsingException e) {
                    logger.warn("Failed to parse Subject Alternative Names for cert {}: {}", cert.getSubjectX500Principal(), e.getMessage());
                }
                details.setSelfSigned(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
                details.setExpired(cert.getNotAfter().before(new Date()));
                details.setNotYetValid(cert.getNotBefore().after(new Date()));
                details.setTrustStatus(determinedTrustStatus);
                details.setRevocationStatus(RevocationStatus.NOT_CHECKED);
                certificateDetailsList.add(details);
            }

            // Step 2: Perform revocation checks for each certificate
            logger.info("Initiating revocation checks for {} certificates in the chain starting with {}.", x509Certs.length, firstCertSubject);
            for (int i = 0; i < x509Certs.length; i++) {
                X509Certificate currentCert = x509Certs[i];
                CertificateDetails currentDetails = certificateDetailsList.get(i);
                String currentCertId = "Cert Subject: " + currentDetails.getSubjectDN() + ", Serial: " + currentDetails.getSerialNumber();
                logger.debug("Performing revocation check for {}.", currentCertId);

                X509Certificate issuerCert = null;
                if (currentDetails.isSelfSigned()) {
                    issuerCert = currentCert; // Self-signed cert is its own issuer for OCSP/CRL context
                    logger.debug("Certificate {} is self-signed, using itself as issuer for revocation check.", currentCertId);
                } else {
                    // Attempt to find the issuer in the provided chain
                    if (i + 1 < x509Certs.length && currentCert.getIssuerX500Principal().equals(x509Certs[i+1].getSubjectX500Principal())) {
                        issuerCert = x509Certs[i+1];
                        logger.debug("Issuer for {} found as next in chain: {}", currentCertId, x509Certs[i+1].getSubjectX500Principal().getName());
                    } else {
                        // Fallback: search the entire chain if not immediately next (e.g. unordered chain)
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
                
                // Call the revocation checker (it handles null issuerCert internally if OCSP/CRL needs it)
                revocationChecker.checkRevocation(currentCert, issuerCert, currentDetails);
                logger.debug("Revocation check completed for {}. Status: {}, Reason: {}", currentCertId, currentDetails.getRevocationStatus(), currentDetails.getFailureReason());

                // If a certificate is found REVOKED, the entire chain's trust is compromised.
                if (currentDetails.getRevocationStatus() == RevocationStatus.REVOKED) {
                    logger.error("Certificate {} is REVOKED. Failing chain validation. Reason: {}", currentCertId, currentDetails.getFailureReason());
                    // Update trust status for all certs in this chain to NOT_TRUSTED.
                    for (CertificateDetails detail : certificateDetailsList) {
                        detail.setTrustStatus(TrustStatus.NOT_TRUSTED);
                        if (detail != currentDetails) { // Avoid overwriting the original failure reason on the revoked cert itself
                           detail.setFailureReason((detail.getFailureReason() == null ? "" : detail.getFailureReason() + "; ") + "Chain invalid due to revoked certificate: " + currentDetails.getSubjectDN());
                        }
                    }
                    // Throw exception to signal chain failure.
                    throw new CertificateException("Certificate chain is invalid: certificate " + currentDetails.getSubjectDN() + " (Serial: " + currentDetails.getSerialNumber() + ") is REVOKED. Reason: " + currentDetails.getFailureReason());
                }
            }
            // If no certificate was revoked, the chain is considered valid from a revocation perspective.
            logger.info("All revocation checks passed for chain starting with {}.", firstCertSubject);
            logger.info("Storing validation results for chain {} in cache.", firstCertSubject);
            CERTIFICATE_CACHE.put(certKey, certificateDetailsList);
            return certificateDetailsList;

        } catch (CertificateException e) { // Catches exceptions from tm.checkServerTrusted OR the explicit throw for REVOKED
            logger.warn("Certificate chain validation failed for chain starting with {}. Reason: {}", firstCertSubject, e.getMessage());
            
            // If certificateDetailsList is empty, it means tm.checkServerTrusted likely failed before population.
            // Populate it now to mark all as NOT_TRUSTED.
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
                            Map<String, String> sanMap = new HashMap<>();
                            for (var sanItem : sans) {
                                Integer type = (Integer) sanItem.get(0);
                                String value = (String) sanItem.get(1);
                                sanMap.put(type.toString(), value);
                            }
                            details.setSubjectAlternativeNames(sanMap);
                        }
                    } catch (CertificateParsingException sanEx) {
                        logger.warn("Failed to parse Subject Alternative Names for cert {} during error handling: {}", cert.getSubjectX500Principal(), sanEx.getMessage());
                    }
                    details.setSelfSigned(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
                    details.setExpired(cert.getNotAfter().before(new Date()));
                    details.setNotYetValid(cert.getNotBefore().after(new Date()));
                    details.setTrustStatus(TrustStatus.NOT_TRUSTED);
                    details.setRevocationStatus(RevocationStatus.NOT_CHECKED); // Revocation checks might not have run
                    details.setFailureReason(e.getMessage()); // Set the primary failure reason
                    certificateDetailsList.add(details);
                 }
            } else {
                // If list was populated, ensure all entries reflect the failure.
                // This is particularly for the case where checkServerTrusted passed, but a subsequent revocation check failed.
                for (CertificateDetails detail : certificateDetailsList) {
                    if (detail.getTrustStatus() != TrustStatus.NOT_TRUSTED) { // Avoid overwriting specific REVOKED failure reason if already set by revocation loop
                        detail.setTrustStatus(TrustStatus.NOT_TRUSTED);
                        detail.setFailureReason((detail.getFailureReason() == null || detail.getFailureReason().isEmpty() ? e.getMessage() : detail.getFailureReason() + "; " + e.getMessage()));
                    }
                }
            }
            // Do not cache this result as trusted.
            logger.warn("Chain validation failed for {}, not caching as trusted.", firstCertSubject);
            throw e; // Re-throw original exception or the one from revocation check
        }
    }

    private String getCertificateKey(X509Certificate cert) {
        return cert.getSerialNumber().toString(16) + "_" + cert.getIssuerX500Principal().getName();
    }

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
                details.setIssuerDN(cert.getIssuerX500Principal().getName());
                details.setVersion(cert.getVersion());
                details.setSerialNumber(cert.getSerialNumber().toString(16).toUpperCase());
                details.setValidFrom(cert.getNotBefore());
                details.setValidUntil(cert.getNotAfter());
                details.setSignatureAlgorithm(cert.getSigAlgName());
                details.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
                 var sans = cert.getSubjectAlternativeNames();
                if (sans != null) {
                    Map<String, String> sanMap = new HashMap<>();
                    for (var san : sans) {
                        Integer type = (Integer) san.get(0);
                        String value = (String) san.get(1);
                        sanMap.put(type.toString(), value);
                    }
                    details.setSubjectAlternativeNames(sanMap);
                }
                details.setSelfSigned(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()));
                details.setExpired(cert.getNotAfter().before(new Date()));
                details.setNotYetValid(cert.getNotBefore().after(new Date()));
                details.setTrustStatus(TrustStatus.NOT_TRUSTED);
                details.setRevocationStatus(RevocationStatus.NOT_CHECKED);
                details.setFailureReason(e.getMessage()); // Main reason for chain failure
                certificateDetailsList.add(details);
            }
            // Do not cache if validation failed with an exception that makes the whole chain untrusted.
            // Or cache it with a specific marker if that's desired. For now, not caching failures.
            throw e; // Re-throw original exception
        }
    }

    private String getCertificateKey(X509Certificate cert) {
        return cert.getSerialNumber().toString(16) + "_" + cert.getIssuerX500Principal().getName();
    }

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
