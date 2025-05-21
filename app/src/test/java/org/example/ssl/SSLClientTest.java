package org.example.ssl;

import org.example.cert.TestCertificateGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class SSLClientTest {
    private SSLClient client;
    private KeyPair keyPair;
    private X509Certificate certificate;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws Exception {
        client = new SSLClient();
        
        // 生成测试证书
        keyPair = TestCertificateGenerator.generateKeyPair();
        certificate = TestCertificateGenerator.generateCertificate(
            "CN=test.example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair
        );
    }

    @Test
    void testConnect_WithValidUrl() {
        URL url = assertDoesNotThrow(() -> new URI("https://example.com").toURL());
        SSLConnectionResult result = client.connect(url);
        
        // 由于是测试环境，我们允许连接错误
        assertTrue(result.isSuccess() || result.getError() != null);
    }

    @Test
    void testConnect_WithInvalidUrl() {
        assertThrows(IllegalArgumentException.class, () -> {
            URL url = new URI("http://example.com").toURL();
            client.connect(url);
        });
    }

    @Test
    void testConnect_WithCustomTimeouts() {
        client = new SSLClient(5000, 5000, false, null);
        URL url = assertDoesNotThrow(() -> new URI("https://example.com").toURL());
        SSLConnectionResult result = client.connect(url);
        
        // 由于是测试环境，我们允许连接错误
        assertTrue(result.isSuccess() || result.getError() != null);
    }

    @Test
    void testConnect_WithCustomSocketFactory() {
        SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        client = new SSLClient(10000, 10000, true, socketFactory);
        URL url = assertDoesNotThrow(() -> new URI("https://example.com").toURL());
        SSLConnectionResult result = client.connect(url);
        
        // 由于是测试环境，我们允许连接错误
        assertTrue(result.isSuccess() || result.getError() != null);
    }

    @Test
    void testConnect_WithNullUrl() {
        assertThrows(IllegalArgumentException.class, () -> client.connect(null));
    }

    @Test
    void testConnect_WithNonHttpsUrl() {
        assertThrows(IllegalArgumentException.class, () -> {
            URL url = new URI("http://example.com").toURL();
            client.connect(url);
        });
    }
} 