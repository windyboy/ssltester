package org.example;

import org.example.cert.CertificateValidator;
import org.example.cert.ClientCertificateManager;
import org.example.config.SSLTestConfig;
import org.example.config.SSLTestConfigFile;
import org.example.exception.SSLTestException;
import org.example.output.ResultFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;

import javax.net.ssl.SSLContext;

/**
 * SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证
 */
@Command(name = "ssltest", 
        description = "SSL测试工具 - 用于验证HTTPS连接，检查证书链和主机名验证",
        mixinStandardHelpOptions = true)
public class SSLTest implements Callable<Integer> {
    private static final Logger logger = LoggerFactory.getLogger(SSLTest.class);

    // Exit codes
    private static final int EXIT_SUCCESS = 0;
    private static final int EXIT_INVALID_ARGS = 1;
    private static final int EXIT_SSL_HANDSHAKE_ERROR = 2;
    private static final int EXIT_CONNECTION_ERROR = 3;
    private static final int EXIT_HOSTNAME_VERIFICATION_ERROR = 5;
    private static final int EXIT_UNEXPECTED_ERROR = 99;

    @CommandLine.Mixin
    private final SSLTestConfig config;
    private final CertificateValidator certValidator;
    private final ResultFormatter resultFormatter;
    private final ClientCertificateManager clientCertManager;
    private final Map<String, Object> result = new HashMap<>();

    // No-arg constructor for CLI use
    public SSLTest() {
        this(new SSLTestConfig());
    }

    // Constructor for test/dependency injection
    public SSLTest(SSLTestConfig config) {
        this.config = config;
        this.certValidator = new CertificateValidator(config.getKeystoreFile(), config.getKeystorePassword());
        this.resultFormatter = new ResultFormatter(config);
        this.clientCertManager = new ClientCertificateManager(config);
    }

    public static void main(String... args) {
        int exitCode = new CommandLine(new SSLTest()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        try {
            if (config.getUrl() == null || config.getUrl().trim().isEmpty()) {
                throw new SSLTestException("URL is required", EXIT_INVALID_ARGS);
            }

            // Load configuration from file if specified
            if (config.getConfigFile() != null) {
                try {
                    Map<String, Object> fileConfig = SSLTestConfigFile.loadConfig(config.getConfigFile());
                    SSLTestConfigFile.applyConfig(fileConfig, config);
                } catch (IOException e) {
                    throw new SSLTestException("Failed to load configuration file: " + e.getMessage(), EXIT_INVALID_ARGS, e);
                }
            }
            
            URL parsedUrl = parseAndValidateUrl(config.getUrl());
            testSSLConnection(parsedUrl);
            resultFormatter.formatAndOutput(result);
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
        resultFormatter.logError(message, cause, exitCode);
        result.put("error", message);
        if (cause != null) {
            result.put("errorCause", cause.getMessage());
        }
        result.put("exitCode", exitCode);
        resultFormatter.formatAndOutput(result);
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

            Certificate[] certs = conn.getServerCertificates();
            X509Certificate[] x509Certs = certValidator.validateCertificateChain(certs);
            validateHostname(conn, url, x509Certs[0]);
            processCertificates(x509Certs);

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
        conn.setConnectTimeout(config.getConnectionTimeout());
        conn.setReadTimeout(config.getReadTimeout());
        conn.setInstanceFollowRedirects(config.isFollowRedirects());

        // Set up client certificate if configured
        try {
            SSLContext sslContext = clientCertManager.createSSLContext();
            if (sslContext != null) {
                conn.setSSLSocketFactory(sslContext.getSocketFactory());
                logger.info("Using client certificate for authentication");
            }
        } catch (Exception e) {
            logger.warn("Failed to set up client certificate: {}", e.getMessage());
        }

        conn.connect();
        return conn;
    }

    private void validateHostname(HttpsURLConnection conn, URL url, X509Certificate cert) throws SSLTestException {
        try {
            Optional<SSLSession> session = conn.getSSLSession();
            if (session.isEmpty()) {
                throw new SSLTestException("SSL session 不可用", EXIT_SSL_HANDSHAKE_ERROR);
            }

            String hostname = url.getHost();
            if (!certValidator.verifyHostname(cert, hostname)) {
                throw new SSLTestException("Hostname verification failed for host " + hostname,
                        EXIT_HOSTNAME_VERIFICATION_ERROR);
            }
            logger.info("→ Hostname verification passed");
            result.put("hostnameVerified", true);
        } catch (Exception e) {
            throw new SSLTestException("主机名验证错误: " + e.getMessage(), EXIT_HOSTNAME_VERIFICATION_ERROR, e);
        }
    }

    private void processCertificates(X509Certificate[] certs) throws Exception {
        logger.info("→ Server sent {} certificate(s):", certs.length);
        result.put("certificateCount", certs.length);
        
        @SuppressWarnings("unchecked")
        Map<String, Object>[] certDetails = (Map<String, Object>[]) new Map[certs.length];
        for (int i = 0; i < certs.length; i++) {
            logger.info("Certificate [{}]", (i + 1));
            certDetails[i] = certValidator.getCertificateInfo(certs[i]);
            logger.info("");
        }
        result.put("certificates", certDetails);
    }
}