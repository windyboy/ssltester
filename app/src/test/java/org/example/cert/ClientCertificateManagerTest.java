package org.example.cert;

import org.example.config.SSLTestConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class ClientCertificateManagerTest {
    private ClientCertificateManager manager;
    private SSLTestConfig config;
    private File certFile;
    private File keyFile;
    private KeyPair keyPair;
    private X509Certificate certificate;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws Exception {
        config = new SSLTestConfig();
        manager = new ClientCertificateManager(config);

        // 生成测试证书和密钥
        keyPair = TestCertificateGenerator.generateKeyPair();
        certificate = TestCertificateGenerator.generateCertificate(
            "CN=client.example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair
        );

        // 创建测试文件
        certFile = new File(tempDir, "client.crt");
        keyFile = new File(tempDir, "client.key");

        // 保存证书到文件
        try (FileOutputStream fos = new FileOutputStream(certFile)) {
            fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
            fos.write(java.util.Base64.getEncoder().encode(certificate.getEncoded()));
            fos.write("\n-----END CERTIFICATE-----\n".getBytes());
        }

        // 保存私钥到文件
        try (FileOutputStream fos = new FileOutputStream(keyFile)) {
            fos.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
            fos.write(java.util.Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
            fos.write("\n-----END PRIVATE KEY-----\n".getBytes());
        }
    }

    @Test
    void testCreateSSLContext_WithValidCertificate() throws Exception {
        config.setClientCertFile(certFile);
        config.setClientKeyFile(keyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.PEM);

        SSLContext sslContext = manager.createSSLContext();
        assertNotNull(sslContext);
    }

    @Test
    void testCreateSSLContext_WithMissingCertificate() {
        // 使用不存在的证书文件
        File nonExistentCertFile = new File(tempDir, "nonexistent.crt");
        config.setClientCertFile(nonExistentCertFile);
        config.setClientKeyFile(keyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.PEM);

        assertThrows(FileNotFoundException.class, () -> manager.createSSLContext());
    }

    @Test
    void testCreateSSLContext_WithMissingKey() {
        // 使用不存在的密钥文件
        File nonExistentKeyFile = new File(tempDir, "nonexistent.key");
        config.setClientCertFile(certFile);
        config.setClientKeyFile(nonExistentKeyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.PEM);

        assertThrows(FileNotFoundException.class, () -> manager.createSSLContext());
    }

    @Test
    void testCreateSSLContext_WithInvalidCertificate() throws Exception {
        config.setClientCertFile(certFile);
        config.setClientKeyFile(keyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.PEM);

        // 损坏证书文件
        Files.write(certFile.toPath(), "invalid content".getBytes());

        assertThrows(Exception.class, () -> manager.createSSLContext());
    }

    @Test
    void testCreateSSLContext_WithInvalidKey() throws Exception {
        config.setClientCertFile(certFile);
        config.setClientKeyFile(keyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.PEM);

        // 损坏密钥文件
        Files.write(keyFile.toPath(), "invalid content".getBytes());

        assertThrows(Exception.class, () -> manager.createSSLContext());
    }

    @Test
    void testCreateSSLContext_WithDERFormat() throws Exception {
        // 创建DER格式的证书和密钥文件
        File derCertFile = new File(tempDir, "client.der");
        File derKeyFile = new File(tempDir, "client.key.der");

        try (FileOutputStream fos = new FileOutputStream(derCertFile)) {
            fos.write(certificate.getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream(derKeyFile)) {
            fos.write(keyPair.getPrivate().getEncoded());
        }

        config.setClientCertFile(derCertFile);
        config.setClientKeyFile(derKeyFile);
        config.setClientCertFormat(SSLTestConfig.CertificateFormat.DER);

        SSLContext sslContext = manager.createSSLContext();
        assertNotNull(sslContext);
    }
} 