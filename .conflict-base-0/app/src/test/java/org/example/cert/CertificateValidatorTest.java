package org.example.cert;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.net.IDN;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CertificateValidatorTest {
    private CertificateValidator validator;
    private File keystoreFile;
    private static final String KEYSTORE_PASSWORD = "password";
    private KeyPair keyPair;
    private X509Certificate testCertificate;
    private X509Certificate ipCertificate;
    private X509Certificate multiDomainCertificate;

    @TempDir
    File tempDir;

    @BeforeEach
    void setUp() throws Exception {
        // Create a test keystore
        keystoreFile = new File(tempDir, "test.jks");
        createTestKeystore();
        validator = new CertificateValidator(keystoreFile, KEYSTORE_PASSWORD);

        // Generate test certificate with standard domains
        keyPair = TestCertificateGenerator.generateKeyPair();
        testCertificate = TestCertificateGenerator.generateCertificate(
            "CN=example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair
        );

        // Generate certificate with IP addresses
        ipCertificate = TestCertificateGenerator.generateCertificate(
            "CN=192.168.1.1, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair,
            null,
            new String[]{"192.168.1.1", "10.0.0.1"}
        );

        // Generate certificate with multiple domains including IDN
        multiDomainCertificate = TestCertificateGenerator.generateCertificate(
            "CN=multi.example.com, O=Test Organization, C=US",
            "CN=Test CA, O=Test Organization, C=US",
            keyPair,
            keyPair,
            new String[]{"xn--80akhbyknj4f.xn--p1ai", "subdomain.example.com", "*.test.example.com"},
            null
        );

        // Add the certificates to the keystore
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(keystoreFile.toURI().toURL().openStream(), KEYSTORE_PASSWORD.toCharArray());
        ks.setCertificateEntry("test-cert", testCertificate);
        ks.setCertificateEntry("ip-cert", ipCertificate);
        ks.setCertificateEntry("multi-domain-cert", multiDomainCertificate);
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    private void createTestKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    @Test
    void testValidateCertificateChain_WithValidCertificates() throws Exception {
        // Create test certificates
        Certificate[] certs = new Certificate[]{testCertificate};

        // Test validation
        X509Certificate[] validatedCerts = validator.validateCertificateChain(certs);

        assertNotNull(validatedCerts);
        assertEquals(certs.length, validatedCerts.length);
    }

    @Test
    void testValidateCertificateChain_WithInvalidCertificates() {
        // Create invalid certificates
        Certificate[] invalidCerts = new Certificate[0];

        // Test validation
        assertThrows(CertificateException.class, () ->
            validator.validateCertificateChain(invalidCerts)
        );
    }

    @Test
    void testGetCertificateInfo() throws Exception {
        // Get certificate info
        Map<String, Object> certInfo = validator.getCertificateInfo(testCertificate);

        // Verify the info
        assertNotNull(certInfo);
        assertTrue(certInfo.containsKey("subjectDN"));
        assertTrue(certInfo.containsKey("issuerDN"));
        assertTrue(certInfo.containsKey("version"));
        assertTrue(certInfo.containsKey("serialNumber"));
        assertTrue(certInfo.containsKey("validFrom"));
        assertTrue(certInfo.containsKey("validUntil"));
        assertTrue(certInfo.containsKey("signatureAlgorithm"));
        assertTrue(certInfo.containsKey("publicKeyAlgorithm"));
    }

    @Test
    void testVerifyHostname_ExactMatch() throws Exception {
        assertTrue(validator.verifyHostname(testCertificate, "example.com"));
    }

    @Test
    void testVerifyHostname_WildcardMatch() throws Exception {
        // 基本通配符匹配
        assertTrue(validator.verifyHostname(testCertificate, "sub.example.com"));

        // 确保通配符只匹配一个级别
        assertFalse(validator.verifyHostname(testCertificate, "sub.sub.example.com"));
    }

    @Test
    void testVerifyHostname_NoMatch() throws Exception {
        assertFalse(validator.verifyHostname(testCertificate, "other.com"));
    }

    @Test
    void testVerifyHostname_WithSubjectAltNames() throws Exception {
        assertTrue(validator.verifyHostname(testCertificate, "alt.example.com"));
    }

    @Test
    void testVerifyHostname_WithIDN() throws Exception {
        // 输出证书中的SAN扩展内容
        System.out.println("\n========== IDN测试开始 ==========");
        Collection<List<?>> sans = multiDomainCertificate.getSubjectAlternativeNames();
        if (sans != null) {
            System.out.println("证书中的SubjectAlternativeNames:");
            for (var san : sans) {
                Integer type = (Integer) san.get(0);
                String value = (String) san.get(1);
                System.out.println("  类型: " + type + ", 值: " + value);
            }
        }

        // 获取证书中的IDN域名
        String certIdnValue = extractCertificateIDN(sans);
        System.out.println("证书中的IDN域名: " + certIdnValue);

        if (certIdnValue != null) {
            // 先测试Punycode格式直接匹配
            System.out.println("\n测试1: 直接使用证书中的Punycode进行验证");
            boolean punycodeResult = validator.verifyHostname(multiDomainCertificate, certIdnValue);
            System.out.println("Punycode直接匹配结果: " + punycodeResult);
            assertTrue(punycodeResult, "使用证书中的Punycode域名应该匹配成功");

            // 将Punycode转换为Unicode并测试
            String unicodeHostname = IDN.toUnicode(certIdnValue);
            System.out.println("\n测试2: 将证书中的Punycode转换为Unicode后验证");
            System.out.println("Punycode转Unicode: " + unicodeHostname);

            boolean unicodeResult = validator.verifyHostname(multiDomainCertificate, unicodeHostname);
            System.out.println("Unicode格式匹配结果: " + unicodeResult);
            assertTrue(unicodeResult, "转换后的Unicode域名应该匹配成功");
        } else {
            fail("证书中没有找到IDN域名");
        }

        System.out.println("========== IDN测试结束 ==========\n");
    }

    /**
     * 从证书的SAN扩展中提取第一个IDN域名
     */
    private String extractCertificateIDN(Collection<List<?>> sans) {
        if (sans == null) return null;

        for (var san : sans) {
            Integer type = (Integer) san.get(0);
            String value = (String) san.get(1);

            // DNS类型 = 2，并且是Punycode格式的IDN
            if (type == 2 && value.contains("xn--")) {
                return value;
            }
        }
        return null;
    }

    @Test
    void testVerifyHostname_WithIPAddress() throws Exception {
        // 验证IP地址匹配
        assertTrue(validator.verifyHostname(ipCertificate, "192.168.1.1"));
        assertTrue(validator.verifyHostname(ipCertificate, "10.0.0.1"));

        // 不匹配的IP地址
        assertFalse(validator.verifyHostname(ipCertificate, "192.168.1.2"));

        // IP地址不应匹配DNS名称
        assertFalse(validator.verifyHostname(testCertificate, "192.168.1.1"));
    }

    @Test
    void testVerifyHostname_EdgeCases() throws Exception {
        // 带有尾部点的域名
        assertTrue(validator.verifyHostname(testCertificate, "example.com."));

        // 大小写不敏感性测试
        assertTrue(validator.verifyHostname(testCertificate, "EXAMPLE.com"));

        // 多级域名匹配测试
        assertTrue(validator.verifyHostname(multiDomainCertificate, "subdomain.example.com"));

        // 通配符边界测试
        assertTrue(validator.verifyHostname(multiDomainCertificate, "www.test.example.com"));
        assertFalse(validator.verifyHostname(multiDomainCertificate, "www.other.example.com"));

        // 空主机名
        assertFalse(validator.verifyHostname(testCertificate, null));
        assertFalse(validator.verifyHostname(testCertificate, ""));
    }
}
