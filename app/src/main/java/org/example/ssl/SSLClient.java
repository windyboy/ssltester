package org.example.ssl;

import java.net.URL;
import java.util.Calendar;
import java.time.ZoneId;
import java.time.Instant;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSLClient {
    private static final Logger logger = LoggerFactory.getLogger(SSLClient.class);
    private static final int MIN_YEAR = 2023;
    private static final int MAX_YEAR = 2024;
    private static final int DEFAULT_CONNECT_TIMEOUT = 10000; // 10 seconds
    private static final int DEFAULT_READ_TIMEOUT = 10000;    // 10 seconds

    private final int connectTimeout;
    private final int readTimeout;
    private final boolean followRedirects;
    private final SSLSocketFactory sslSocketFactory;

    public SSLClient() {
        this(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, false, null);
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

        // 在连接前检查系统时间
        checkSystemTime();
        
        HttpsURLConnection conn = null;
        try {
            logger.info("Connecting to {}...", url);
            conn = (HttpsURLConnection) url.openConnection();
            
            // 配置连接
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setInstanceFollowRedirects(followRedirects);
            
            // 设置SSL配置
            if (sslSocketFactory != null) {
                conn.setSSLSocketFactory(sslSocketFactory);
            }

            // 建立连接
            conn.connect();
            
            // 获取连接信息
            int responseCode = conn.getResponseCode();
            String cipherSuite = conn.getCipherSuite();
            X509Certificate[] certs = (X509Certificate[]) conn.getServerCertificates();
            
            // 验证证书链
            List<X509Certificate> certChain = new ArrayList<>();
            for (X509Certificate cert : certs) {
                certChain.add(cert);
            }

            // 验证主机名
            boolean hostnameVerified = verifyHostname(conn, url.getHost(), certs[0]);
            
            return new SSLConnectionResult(
                true,
                "Connection successful",
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
                "SSL handshake failed",
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
                "Connection timeout",
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
                "Connection failed",
                null,
                e,
                null,
                0,
                false
            );
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * 验证主机名是否与证书匹配
     */
    private boolean verifyHostname(HttpsURLConnection conn, String hostname, X509Certificate cert) {
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
     * 检查系统时间是否可能不准确
     * 检查内容包括：
     * 1. 年份是否在合理范围内
     * 2. 系统时间是否与当前时间相差太大
     * 3. 时区设置是否合理
     */
    private void checkSystemTime() {
        try {
            Calendar cal = Calendar.getInstance();
            int currentYear = cal.get(Calendar.YEAR);
            ZoneId systemZone = ZoneId.systemDefault();
            Instant now = Instant.now();
            
            // 检查年份
            if (currentYear < MIN_YEAR || currentYear > MAX_YEAR) {
                logger.warn("⚠️ 系统时间可能不准确！当前年份: {}，这会导致证书验证问题", currentYear);
                logger.warn("请同步您的系统时间以确保证书验证正确");
            }
            
            // 检查时区
            if (systemZone.getId().equals("GMT") || systemZone.getId().equals("UTC")) {
                logger.warn("⚠️ 系统时区设置为 {}，这可能会影响证书验证", systemZone.getId());
                logger.warn("建议设置正确的本地时区");
            }
            
            // 检查时间偏差（与当前时间比较）
            long timeDiff = Math.abs(System.currentTimeMillis() - now.toEpochMilli());
            if (timeDiff > 300000) { // 5分钟
                logger.warn("⚠️ 系统时间与当前时间相差超过5分钟，这可能会影响证书验证");
                logger.warn("请同步您的系统时间");
            }
        } catch (Exception e) {
            logger.error("检查系统时间时发生错误", e);
        }
    }
}
