package org.example.ssl;

import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSLClient {
    private static final Logger logger = LoggerFactory.getLogger(SSLClient.class);
    private static final int DEFAULT_TIMEOUT = 10000; // 10 seconds

    private final int connectTimeout;
    private final int readTimeout;
    private final boolean followRedirects;
    private final SSLSocketFactory sslSocketFactory;
    private HttpsURLConnection currentConnection;

    public SSLClient() {
        this(DEFAULT_TIMEOUT, DEFAULT_TIMEOUT, false, null);
    }

    public SSLClient(int connectTimeout, int readTimeout, boolean followRedirects, SSLSocketFactory sslSocketFactory) {
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.followRedirects = followRedirects;
        this.sslSocketFactory = sslSocketFactory;
    }

    /**
     * 建立SSL连接并验证证书
     * @param url 要连接的HTTPS URL
     * @return SSLConnectionResult 包含连接结果和证书信息
     * @throws IllegalArgumentException 如果URL无效
     */
    public SSLConnectionResult connect(URL url) {
        if (url == null) {
            throw new IllegalArgumentException("URL cannot be null");
        }
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("URL must use HTTPS protocol");
        }
        
        try {
            logger.info("Connecting to {}...", url);
            currentConnection = (HttpsURLConnection) url.openConnection();
            
            // 配置连接
            currentConnection.setConnectTimeout(connectTimeout);
            currentConnection.setReadTimeout(readTimeout);
            currentConnection.setInstanceFollowRedirects(followRedirects);
            
            // 设置SSL配置
            if (sslSocketFactory != null) {
                currentConnection.setSSLSocketFactory(sslSocketFactory);
            }

            // 建立连接
            currentConnection.connect();
            
            // 获取连接信息
            int responseCode = currentConnection.getResponseCode();
            String cipherSuite = currentConnection.getCipherSuite();
            X509Certificate[] certs = (X509Certificate[]) currentConnection.getServerCertificates();
            
            // 验证证书链
            List<X509Certificate> certChain = new ArrayList<>();
            for (X509Certificate cert : certs) {
                certChain.add(cert);
            }

            // 验证主机名
            boolean hostnameVerified = verifyHostname(currentConnection, url.getHost());
            
            return new SSLConnectionResult(
                true,
                certChain,
                null,
                cipherSuite,
                responseCode,
                hostnameVerified
            );

        } catch (javax.net.ssl.SSLHandshakeException e) {
            logger.error("SSL handshake failed: {}", e.getMessage());
            return new SSLConnectionResult(
                false,
                null,
                e,
                null,
                0,
                false
            );
        } catch (java.net.SocketTimeoutException e) {
            logger.error("Connection timeout: {}", e.getMessage());
            return new SSLConnectionResult(
                false,
                null,
                e,
                null,
                0,
                false
            );
        } catch (Exception e) {
            logger.error("Connection failed: {}", e.getMessage());
            return new SSLConnectionResult(
                false,
                null,
                e,
                null,
                0,
                false
            );
        }
    }

    /**
     * 验证主机名是否与证书匹配
     */
    private boolean verifyHostname(HttpsURLConnection conn, String hostname) {
        try {
            var session = conn.getSSLSession();
            if (session.isEmpty()) {
                logger.error("No SSL session available");
                return false;
            }
            return conn.getHostnameVerifier().verify(hostname, session.get());
        } catch (Exception e) {
            logger.error("Hostname verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 关闭当前连接
     */
    public void close() {
        if (currentConnection != null) {
            currentConnection.disconnect();
            currentConnection = null;
        }
    }
}
