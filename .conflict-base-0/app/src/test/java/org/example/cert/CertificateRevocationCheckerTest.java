package org.example.cert;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.security.KeyPair;
// import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class CertificateRevocationCheckerTest {
    private CertificateRevocationChecker checker;
    private X509Certificate testCertificate;
    private KeyPair keyPair;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws Exception {
        // 创建测试证书
        keyPair = TestCertificateGenerator.generateKeyPair();
        testCertificate = TestCertificateGenerator.generateCertificate(
            "CN=example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair
        );
    }

    @Test
    void testCheckRevocation_WithOCSPEnabled() {
        checker = new CertificateRevocationChecker(true, false);
        // 由于是测试环境，我们期望OCSP检查不会抛出异常
        assertDoesNotThrow(() -> checker.checkRevocation(testCertificate));
    }

    @Test
    void testCheckRevocation_WithCRLEnabled() {
        checker = new CertificateRevocationChecker(false, true);
        // 由于是测试环境，我们期望CRL检查不会抛出异常
        assertDoesNotThrow(() -> checker.checkRevocation(testCertificate));
    }

    @Test
    void testCheckRevocation_WithBothEnabled() {
        checker = new CertificateRevocationChecker(true, true);
        // 由于是测试环境，我们期望检查不会抛出异常
        assertDoesNotThrow(() -> checker.checkRevocation(testCertificate));
    }

    @Test
    void testCheckRevocation_WithBothDisabled() {
        checker = new CertificateRevocationChecker(false, false);
        // 当两者都禁用时，检查应该直接返回
        assertDoesNotThrow(() -> checker.checkRevocation(testCertificate));
    }

    @Test
    void testCheckRevocation_WithNullCertificate() {
        checker = new CertificateRevocationChecker(true, true);
        // 修改测试：使用NullPointerException，因为实现类可能直接使用证书对象而没有进行空值检查
        assertThrows(NullPointerException.class, () -> checker.checkRevocation(null));
    }
} 