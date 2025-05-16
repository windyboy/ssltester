package org.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证
 */
@Command(name = "ssltest", 
        description = "SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证",
        mixinStandardHelpOptions = true)
public class SSLTest implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(SSLTest.class);

    @Parameters(index = "0", description = "要测试的HTTPS URL")
    private String url;

    @Option(names = {"-t", "--timeout"}, description = "连接超时时间(毫秒)")
    private int connectionTimeout = 5000;

    @Option(names = {"-r", "--read-timeout"}, description = "读取超时时间(毫秒)")
    private int readTimeout = 5000;

    @Option(names = {"-f", "--follow-redirects"}, description = "是否跟随重定向")
    private boolean followRedirects = false;

    @Option(names = {"-k", "--keystore"}, description = "信任库文件路径")
    private File keystoreFile;

    @Option(names = {"-p", "--keystore-password"}, description = "信任库密码", interactive = true)
    private String keystorePassword;

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private File outputFile;

    @Option(names = {"--format"}, description = "输出格式: TEXT, JSON, YAML", defaultValue = "TEXT")
    private OutputFormat format = OutputFormat.TEXT;

    @Option(names = {"-v", "--verbose"}, description = "显示详细输出")
    private boolean verbose = false;

    // 常量配置
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault());
    private static final String INDENT = "   ";

    // 退出状态码
    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_INVALID_ARGS = 1;
    private static final int EXIT_SSL_HANDSHAKE_ERROR = 2;
    private static final int EXIT_CONNECTION_ERROR = 3;
    private static final int EXIT_CERT_VALIDATION_ERROR = 4;
    private static final int EXIT_HOSTNAME_VERIFICATION_ERROR = 5;
    private static final int EXIT_UNEXPECTED_ERROR = 99;

    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final Map<String, Object> result = new HashMap<>();

    public static void main(String... args) {
        int exitCode = new CommandLine(new SSLTest()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        try {
            URL parsedUrl = parseAndValidateUrl(url);
            testSSLConnection(parsedUrl);
            outputResult();
            return EXIT_SUCCESS;
        } catch (SSLTestException e) {
            handleError(e.getMessage(), e.getCause(), e.getExitCode());
            return e.getExitCode();
        } catch (Exception e) {
            handleError("未预期的错误: " + e.getMessage(), e, EXIT_UNEXPECTED_ERROR);
            return EXIT_UNEXPECTED_ERROR;
        }
    }

    private void handleError(String message, Throwable cause, int exitCode) {
        logger.error("❌ {}", message);
        if (cause != null && verbose) {
            logger.error("详细错误信息:", cause);
        }
        result.put("error", message);
        if (cause != null) {
            result.put("errorCause", cause.getMessage());
        }
        result.put("exitCode", exitCode);
        outputResult();
    }

    private void outputResult() {
        try {
            String output;
            switch (format) {
                case JSON:
                    output = jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
                    break;
                case YAML:
                    output = yamlMapper.writeValueAsString(result);
                    break;
                default:
                    return; // TEXT format is handled by direct logging
            }

            if (outputFile != null) {
                try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                    writer.println(output);
                }
            } else {
                System.out.println(output);
            }
        } catch (Exception e) {
            logger.error("输出结果时发生错误: {}", e.getMessage());
        }
    }

    private URL parseAndValidateUrl(String urlStr) throws SSLTestException {
        try {
            URL url = new URI(urlStr).toURL();
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                throw new SSLTestException("URL 必须使用 HTTPS 协议", EXIT_INVALID_ARGS);
            }
            return url;
        } catch (Exception e) {
            throw new SSLTestException("无效的 URL: " + e.getMessage(), EXIT_INVALID_ARGS, e);
        }
    }

    private void testSSLConnection(URL url) throws Exception {
        HttpsURLConnection conn = null;
        try {
            conn = setupConnection(url);
            int responseCode = conn.getResponseCode();
            String cipherSuite = conn.getCipherSuite();
            
            logger.info("→ HTTP Status  : {}", responseCode);
            logger.info("→ Cipher Suite : {}", cipherSuite);
            
            result.put("httpStatus", responseCode);
            result.put("cipherSuite", cipherSuite);

            X509Certificate[] x509Certs = validateCertificateChain(conn);
            performHostnameVerification(conn, url, x509Certs[0]);
            printCertificateDetails(x509Certs);

            logger.info("✅ SSL handshake and HTTP request succeeded.");
            result.put("status", "success");
        } catch (javax.net.ssl.SSLHandshakeException e) {
            throw new SSLTestException("SSL handshake failed: " + e.getMessage(), EXIT_SSL_HANDSHAKE_ERROR, e);
        } catch (Exception e) {
            throw new SSLTestException("Error during request: " + e.getMessage(), EXIT_CONNECTION_ERROR, e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private HttpsURLConnection setupConnection(URL url) throws java.io.IOException {
        logger.info("Connecting to {} …", url);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setConnectTimeout(connectionTimeout);
        conn.setReadTimeout(readTimeout);
        conn.setInstanceFollowRedirects(followRedirects);
        conn.connect();
        return conn;
    }

    private X509Certificate[] validateCertificateChain(HttpsURLConnection conn) throws SSLTestException {
        try {
            Certificate[] certs = conn.getServerCertificates();
            X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            if (keystoreFile != null) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(keystoreFile.toURI().toURL().openStream(), 
                        keystorePassword != null ? keystorePassword.toCharArray() : null);
                tmf.init(ks);
            } else {
                tmf.init((KeyStore) null);
            }
            
            X509TrustManager tm = findX509TrustManager(tmf);

            String sigAlg = x509Certs[0].getSigAlgName();
            String auth = determineAuthType(sigAlg);

            try {
                tm.checkServerTrusted(x509Certs, auth);
                logger.info("→ Certificate chain trusted");
                result.put("certificateTrusted", true);
            } catch (CertificateException ce) {
                throw new SSLTestException("Certificate validation failed (" + auth + "): " + ce.getMessage(),
                        EXIT_CERT_VALIDATION_ERROR, ce);
            }
            return x509Certs;
        } catch (Exception e) {
            throw new SSLTestException("证书验证过程中出现错误: " + e.getMessage(), EXIT_CERT_VALIDATION_ERROR, e);
        }
    }

    private String determineAuthType(String sigAlg) {
        String auth = sigAlg.substring(sigAlg.toUpperCase().indexOf("WITH") + 4);
        return "ECDSA".equalsIgnoreCase(auth) ? "ECDHE_ECDSA" : auth;
    }

    private void performHostnameVerification(HttpsURLConnection conn, URL url, X509Certificate cert)
            throws SSLTestException {
        try {
            Optional<SSLSession> session = conn.getSSLSession();
            if (session.isEmpty()) {
                throw new SSLTestException("SSL session 不可用", EXIT_SSL_HANDSHAKE_ERROR);
            }

            String hostname = url.getHost();
            if (!verifyHostname(cert, hostname)) {
                throw new SSLTestException("Hostname verification failed for host " + hostname,
                        EXIT_HOSTNAME_VERIFICATION_ERROR);
            }
            logger.info("→ Hostname verification passed");
            result.put("hostnameVerified", true);
        } catch (Exception e) {
            throw new SSLTestException("主机名验证错误: " + e.getMessage(), EXIT_HOSTNAME_VERIFICATION_ERROR, e);
        }
    }

    private boolean verifyHostname(X509Certificate cert, String hostname) {
        try {
            // Check Subject Alternative Names first
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (var san : sans) {
                    Integer type = (Integer) san.get(0);
                    String value = (String) san.get(1);
                    
                    // DNS type = 2
                    if (type == 2) {
                        if (matchesHostname(value, hostname)) {
                            return true;
                        }
                    }
                }
            }

            // Fallback to Common Name in Subject DN
            String subjectDN = cert.getSubjectX500Principal().getName();
            String[] parts = subjectDN.split(",");
            for (String part : parts) {
                if (part.startsWith("CN=")) {
                    String cn = part.substring(3);
                    if (matchesHostname(cn, hostname)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matchesHostname(String pattern, String hostname) {
        // Convert to lowercase for case-insensitive comparison
        pattern = pattern.toLowerCase();
        hostname = hostname.toLowerCase();

        // Handle wildcard certificates
        if (pattern.startsWith("*.")) {
            // Wildcard must be in the leftmost label
            String patternDomain = pattern.substring(2);
            String hostnameDomain = hostname;
            
            // Check if hostname has enough labels
            int dotCount = hostname.length() - hostname.replace(".", "").length();
            if (dotCount < 1) {
                return false;
            }
            
            // Get the domain part of the hostname (everything after the first dot)
            int firstDot = hostname.indexOf('.');
            if (firstDot > 0) {
                hostnameDomain = hostname.substring(firstDot + 1);
            }
            
            return hostnameDomain.equals(patternDomain);
        }
        
        // Direct match
        return pattern.equals(hostname);
    }

    private X509TrustManager findX509TrustManager(TrustManagerFactory tmf) throws SSLTestException {
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new SSLTestException("没有找到X509TrustManager", EXIT_CERT_VALIDATION_ERROR);
    }

    private void printCertificateDetails(X509Certificate[] certs) throws Exception {
        logger.info("→ Server sent {} certificate(s):", certs.length);
        result.put("certificateCount", certs.length);
        
        Map<String, Object>[] certDetails = new Map[certs.length];
        for (int i = 0; i < certs.length; i++) {
            logger.info("Certificate [{}]", (i + 1));
            if (certs[i] instanceof X509Certificate xc) {
                certDetails[i] = printCertInfo(xc);
            } else {
                logger.info("{} (非 X.509 证书，类型: {})", INDENT, certs[i].getType());
                certDetails[i] = Map.of("type", certs[i].getType());
            }
            logger.info("");
        }
        result.put("certificates", certDetails);
    }

    private Map<String, Object> printCertInfo(X509Certificate cert) throws Exception {
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

        printSubjectAlternativeNames(cert, certInfo);
        return certInfo;
    }

    private void printSubjectAlternativeNames(X509Certificate cert, Map<String, Object> certInfo) throws Exception {
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

    private enum OutputFormat {
        TEXT, JSON, YAML
    }

    private static class SSLTestException extends Exception {
        private final int exitCode;

        public SSLTestException(String message, int exitCode) {
            super(message);
            this.exitCode = exitCode;
        }

        public SSLTestException(String message, int exitCode, Throwable cause) {
            super(message, cause);
            this.exitCode = exitCode;
        }

        public int getExitCode() {
            return exitCode;
        }
    }
}