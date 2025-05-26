package org.example.cert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.InputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final Map<String, Boolean> CERTIFICATE_CACHE = new ConcurrentHashMap<>();

    private final File keystoreFile;
    private final String keystorePassword;
    private final CertificateRevocationChecker revocationChecker = new CertificateRevocationChecker(true, false);

    public CertificateValidator(File keystoreFile, String keystorePassword) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
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

    public X509Certificate[] validateCertificateChain(Certificate[] certs, String authTypeFromCipher) throws CertificateException {
        if (certs == null || certs.length == 0) {
            throw new CertificateException("No certificates provided");
        }

        // 检查系统时间
        checkSystemTime();

        X509Certificate[] x509Certs = Arrays.stream(certs)
                .map(cert -> (X509Certificate) cert)
                .toArray(X509Certificate[]::new);
        
        // 检查缓存
        String certKey = getCertificateKey(x509Certs[0]);
        Boolean cachedResult = CERTIFICATE_CACHE.get(certKey);
        if (cachedResult != null) {
            if (cachedResult) {
                logger.info("→ Certificate chain trusted (from cache)");
                return x509Certs;
            } else {
                throw new CertificateException("Certificate chain not trusted (from cache)");
            }
        }

        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);

        try {
            tm.checkServerTrusted(x509Certs, authTypeFromCipher);
            logger.info("→ Certificate chain trusted");
            CERTIFICATE_CACHE.put(certKey, true);

            // Check revocation status for each certificate in the chain
            for (X509Certificate cert : x509Certs) {
                revocationChecker.checkRevocation(cert);
            }

            return x509Certs;
        } catch (CertificateException e) {
            CERTIFICATE_CACHE.put(certKey, false);
            throw e;
        }
    }

    private String getCertificateKey(X509Certificate cert) {
        return cert.getSerialNumber().toString(16) + "_" + cert.getIssuerX500Principal().getName();
    }

    private TrustManagerFactory initializeTrustManagerFactory() throws CertificateException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            PKIXBuilderParameters pkixParams;

            if (keystoreFile != null) {
                logger.debug("Using custom keystore: {}", keystoreFile.getAbsolutePath());
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(keystoreFile.toURI().toURL().openStream(),
                        keystorePassword != null ? keystorePassword.toCharArray() : null);
                tmf.init(ks);
                pkixParams = new PKIXBuilderParameters(ks, new X509CertSelector());
            } else {
                logger.debug("Using system default truststore.");
                KeyStore systemTrustStore = getSystemTrustStore();
                pkixParams = new PKIXBuilderParameters(systemTrustStore, new X509CertSelector());
            }

            pkixParams.setRevocationEnabled(true);
            logger.debug("Revocation checking enabled in PKIXBuilderParameters.");

            tmf.init(new CertPathTrustManagerParameters(pkixParams));
            return tmf;
        } catch (Exception e) {
            throw new CertificateException("Failed to initialize PKIX trust manager: " + e.getMessage(), e);
        }
    }

    /**
     * Loads the default system truststore (either 'jssecacerts' or 'cacerts' from the JRE's security directory).
     *
     * @return The loaded {@link KeyStore} object representing the system truststore.
     * @throws CertificateException If the truststore file cannot be found, loaded, or if there's a KeyStore error.
     */
    private KeyStore getSystemTrustStore() throws CertificateException {
        try {
            String javaHome = System.getProperty("java.home");
            Path trustStorePath = Paths.get(javaHome, "lib", "security", "jssecacerts");
            if (!Files.exists(trustStorePath)) {
                trustStorePath = Paths.get(javaHome, "lib", "security", "cacerts");
            }

            if (!Files.exists(trustStorePath)) {
                throw new CertificateException("Could not find jssecacerts or cacerts in " + javaHome);
            }
            logger.debug("Loading system truststore from: {}", trustStorePath);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream fis = Files.newInputStream(trustStorePath)) {
                // Default password for cacerts is "changeit"
                trustStore.load(fis, "changeit".toCharArray());
            }
            return trustStore;
        } catch (KeyStoreException e) {
             throw new CertificateException("Failed to instantiate KeyStore for system truststore: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new CertificateException("Failed to load system truststore: " + e.getMessage(), e);
        }
    }

    /**
     * Finds and returns an {@link X509TrustManager} from the provided {@link TrustManagerFactory}.
     *
     * @param tmf The {@link TrustManagerFactory} from which to extract the trust manager.
     * @return The first {@link X509TrustManager} found.
     * @throws CertificateException If no X509TrustManager is found in the factory.
     */
    private X509TrustManager findX509TrustManager(TrustManagerFactory tmf) throws CertificateException {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new CertificateException("No X509TrustManager found");
    }

    /**
     * Extracts detailed information from a given X.509 certificate.
     * Information includes Subject DN, Issuer DN, version, serial number, validity period,
     * signature algorithm, public key algorithm, and Subject Alternative Names (SANs).
     *
     * @param cert The {@link X509Certificate} to extract information from.
     * @return A {@link Map} where keys are descriptive strings (e.g., "subjectDN", "serialNumber")
     *         and values are the corresponding certificate details.
     * @throws Exception If there's an error parsing the certificate (e.g., {@link java.security.cert.CertificateEncodingException}).
     */
    public Map<String, Object> getCertificateInfo(X509Certificate cert) throws Exception {
        Map<String, Object> certInfo = new HashMap<>();


        String subjectDN = cert.getSubjectX500Principal().getName();
        String issuerDN = cert.getIssuerX500Principal().getName();
        int version = cert.getVersion();
        String serialNumber = cert.getSerialNumber().toString(16).toUpperCase();
        String validFrom = DATE_FORMATTER.format(cert.getNotBefore().toInstant());
        String validUntil = DATE_FORMATTER.format(cert.getNotAfter().toInstant());
        String sigAlg = cert.getSigAlgName();
        String pubKeyAlg = cert.getPublicKey().getAlgorithm();

        certInfo.put("subjectDN", subjectDN);
        certInfo.put("issuerDN", issuerDN);
        certInfo.put("version", version);
        certInfo.put("serialNumber", serialNumber);
        certInfo.put("validFrom", validFrom);
        certInfo.put("validUntil", validUntil);
        certInfo.put("signatureAlgorithm", sigAlg);
        certInfo.put("publicKeyAlgorithm", pubKeyAlg);

        // 添加 Subject Alternative Names
        var sans = cert.getSubjectAlternativeNames();
        if (sans != null) {
            Map<String, String> sanMap = new HashMap<>();
            for (var san : sans) {
                Integer type = (Integer) san.get(0);
                String value = (String) san.get(1);
                sanMap.put(type.toString(), value);
            }
            certInfo.put("subjectAlternativeNames", sanMap);
        }

        return certInfo;
    }

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

    /**
     * Matches a given hostname against a pattern, which can be an exact domain name or a wildcard domain name.
     * Wildcard logic:
     * <ul>
     *   <li>A pattern like "*.example.com" matches "www.example.com" but not "example.com" or "sub.www.example.com".</li>
     *   <li>The wildcard '*' must represent a single domain label and cannot include dots.</li>
     *   <li>Patterns like "*" or "*." are considered invalid.</li>
     *   <li>Matching is case-insensitive.</li>
     * </ul>
     *
     * @param pattern  The pattern from the certificate's SAN or CN (e.g., "example.com", "*.example.com").
     * @param hostname The hostname to match against the pattern.
     * @return {@code true} if the hostname matches the pattern, {@code false} otherwise.
     */
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
