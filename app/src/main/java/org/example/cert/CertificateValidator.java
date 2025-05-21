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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final String INDENT = "   ";

    private final File keystoreFile;
    private final String keystorePassword;

    public CertificateValidator(File keystoreFile, String keystorePassword) {
        this.keystoreFile = keystoreFile;
        this.keystorePassword = keystorePassword;
    }

    public X509Certificate[] validateCertificateChain(Certificate[] certs) throws CertificateException {
        if (certs == null || certs.length == 0) {
            throw new CertificateException("No certificates provided");
        }
        X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
        TrustManagerFactory tmf = initializeTrustManagerFactory();
        X509TrustManager tm = findX509TrustManager(tmf);

        String sigAlg = x509Certs[0].getSigAlgName();
        String auth = determineAuthType(sigAlg);

        tm.checkServerTrusted(x509Certs, auth);
        logger.info("→ Certificate chain trusted");
        return x509Certs;
    }

    private TrustManagerFactory initializeTrustManagerFactory() throws CertificateException {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if (keystoreFile != null) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(keystoreFile.toURI().toURL().openStream(),
                        keystorePassword != null ? keystorePassword.toCharArray() : null);
                tmf.init(ks);
            } else {
                tmf.init((KeyStore) null);
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
        String auth = sigAlg.substring(sigAlg.toUpperCase().indexOf("WITH") + 4);
        return "ECDSA".equalsIgnoreCase(auth) ? "ECDHE_ECDSA" : auth;
    }

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

        logger.info("{} Subject DN    : {}", INDENT, subjectDN);
        logger.info("{} Issuer DN     : {}", INDENT, issuerDN);
        logger.info("{} Version       : {}", INDENT, version);
        logger.info("{} Serial Number : {}", INDENT, serialNumber);
        logger.info("{} Valid From    : {}", INDENT, validFrom);
        logger.info("{} Valid Until   : {}", INDENT, validUntil);
        logger.info("{} Sig. Algorithm: {}", INDENT, sigAlg);
        logger.info("{} PubKey Alg    : {}", INDENT, pubKeyAlg);

        certInfo.put("subjectDN", subjectDN);
        certInfo.put("issuerDN", issuerDN);
        certInfo.put("version", version);
        certInfo.put("serialNumber", serialNumber);
        certInfo.put("validFrom", validFrom);
        certInfo.put("validUntil", validUntil);
        certInfo.put("signatureAlgorithm", sigAlg);
        certInfo.put("publicKeyAlgorithm", pubKeyAlg);

        addSubjectAlternativeNames(cert, certInfo);
        return certInfo;
    }

    private void addSubjectAlternativeNames(X509Certificate cert, Map<String, Object> certInfo) throws Exception {
        var sans = cert.getSubjectAlternativeNames();
        if (sans != null) {
            logger.info("{} SubjectAltNames:", INDENT);
            Map<String, String> sanMap = new HashMap<>();
            for (var san : sans) {
                Integer type = (Integer) san.get(0);
                String value = (String) san.get(1);
                logger.info("{}   • {}: {}", INDENT, type, value);
                sanMap.put(type.toString(), value);
            }
            certInfo.put("subjectAlternativeNames", sanMap);
        }
    }

    public boolean verifyHostname(X509Certificate cert, String hostname) {
        try {
            if (hostname == null) {
                return false;
            }

            System.out.println("[DEBUG] 输入主机名: " + hostname);

            // 标准化主机名 (处理国际化域名)
            String normalizedHostname = normalizeHostname(hostname);
            System.out.println("[DEBUG] 标准化后主机名: " + normalizedHostname);

            // 检查主机名是否为IP地址
            boolean isIpAddress = isIpAddress(normalizedHostname);
            System.out.println("[DEBUG] 是否IP地址: " + isIpAddress);

            // 首先检查SubjectAlternativeNames
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                System.out.println("[DEBUG] 证书包含 " + sans.size() + " 个SAN条目");
                for (var san : sans) {
                    Integer type = (Integer) san.get(0);
                    String value = (String) san.get(1);
                    System.out.println("[DEBUG] SAN条目: 类型=" + type + ", 值=" + value);

                    // DNS类型 = 2
                    if (type == 2 && !isIpAddress) {
                        String normalizedValue = normalizeHostname(value);
                        System.out.println("[DEBUG] 标准化SAN值: " + normalizedValue);
                        System.out.println("[DEBUG] 比较: " + normalizedValue + " vs " + normalizedHostname);

                        if (normalizedValue.equals(normalizedHostname)) {
                            System.out.println("[DEBUG] 直接匹配成功!");
                            logger.debug("Hostname {} matched with SAN DNS: {}", normalizedHostname, value);
                            return true;
                        } else if (matchesHostname(normalizedValue, normalizedHostname)) {
                            System.out.println("[DEBUG] 通配符匹配成功!");
                            logger.debug("Hostname {} matched with SAN DNS (wildcard): {}", normalizedHostname, value);
                            return true;
                        }
                    }
                    // IP类��� = 7
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
                System.out.println("[DEBUG] IDN转换: " + hostname + " -> " + asciiForm);
            }
            return asciiForm;

        } catch (Exception e) {
            System.out.println("[ERROR] IDN转换失败: " + hostname + ", 错误: " + e.getMessage());
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
