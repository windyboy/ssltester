package org.example.cert

import kotlin.test.*
import java.io.File
import java.io.FileOutputStream
import java.net.IDN
import java.security.KeyPair
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateException
import org.example.config.SSLTestConfig
import java.security.cert.X509Certificate
import java.util.*
import java.security.KeyPairGenerator
import kotlin.io.path.createTempDirectory
import java.nio.file.Path

class CertificateValidatorTest {
    private lateinit var validator: CertificateValidator
    private lateinit var keystoreFile: File
    private lateinit var keyPair: KeyPair
    private lateinit var testCertificate: X509Certificate
    private lateinit var ipCertificate: X509Certificate
    private lateinit var multiDomainCertificate: X509Certificate
    private lateinit var tempDir: File
    private lateinit var certGenerator: TestCertificateGenerator
    private lateinit var testCertificateChain: List<X509Certificate>

    companion object {
        private const val KEYSTORE_PASSWORD = "password"
    }

    @BeforeTest
    fun setUp() {
        keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val tempDirPath: Path = createTempDirectory()
        tempDir = tempDirPath.toFile()
        keystoreFile = File(tempDir, "test.jks")
        createTestKeystore()
        // Create a default SSLTestConfig for the validator
        val testConfig = SSLTestConfig().apply {
            // Set keystore properties in the config for the validator to use
            this.keystoreFile = this@CertificateValidatorTest.keystoreFile
            this.keystorePassword = KEYSTORE_PASSWORD
            // Set any other specific config properties needed for tests, e.g.
            // this.checkOCSP = true
            // this.checkCRL = true
        }
        validator = CertificateValidator(testConfig)
        certGenerator = TestCertificateGenerator()

        // Generate CA certificate
        val caCertificate = certGenerator.generateCACertificate()
        val caKey = keyPair.private

        // Generate leaf certificates signed by CA
        testCertificate = certGenerator.generateLeafCertificate(
            subject = "CN=Test Certificate",
            issuerCert = caCertificate,
            issuerKey = caKey,
            dnsNames = arrayOf("example.com", "alt.example.com", "test.example.com"),
            ipAddresses = arrayOf("192.168.1.1")
        )
        testCertificateChain = listOf(testCertificate, caCertificate)

        ipCertificate = certGenerator.generateLeafCertificate(
            subject = "CN=192.168.1.1, O=Test Organization, C=US",
            issuerCert = caCertificate,
            issuerKey = caKey,
            ipAddresses = arrayOf("192.168.1.1", "10.0.0.1")
        )

        multiDomainCertificate = certGenerator.generateLeafCertificate(
            subject = "CN=multi.example.com, O=Test Organization, C=US",
            issuerCert = caCertificate,
            issuerKey = caKey,
            dnsNames = arrayOf("xn--80akhbyknj4f.xn--p1ai", "subdomain.example.com", "*.test.example.com")
        )

        // Add the certificates to the keystore
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(keystoreFile.toURI().toURL().openStream(), KEYSTORE_PASSWORD.toCharArray())
        ks.setCertificateEntry("test-cert", testCertificate)
        ks.setCertificateEntry("ip-cert", ipCertificate)
        ks.setCertificateEntry("multi-domain-cert", multiDomainCertificate)
        ks.setCertificateEntry("ca-cert", caCertificate)
        FileOutputStream(keystoreFile).use { fos ->
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray())
        }
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    private fun createTestKeystore() {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        ks.load(null, null)
        FileOutputStream(keystoreFile).use { fos ->
            ks.store(fos, KEYSTORE_PASSWORD.toCharArray())
        }
    }

    @Test
    fun `test validate certificate chain with valid chain`() {
        val result = validator.validateCertificateChain(testCertificateChain.toTypedArray(), "test.example.com")
        assertNotNull(result)
        assertTrue(result.isNotEmpty())
    }

    @Test
    fun `test validate certificate chain with invalid hostname`() {
        assertFailsWith<CertificateException> {
            validator.validateCertificateChain(testCertificateChain.toTypedArray(), "invalid.example.com")
        }
    }

    @Test
    fun `test validate certificate chain with empty chain`() {
        assertFailsWith<CertificateException> {
            validator.validateCertificateChain(emptyArray(), "test.example.com")
        }
    }

    @Test
    fun `test validate certificate chain with null chain`() {
        assertFailsWith<CertificateException> {
            validator.validateCertificateChain(null, "test.example.com")
        }
    }

    @Test
    fun `test get certificate info`() {
        // Get certificate info
        val certInfo = validator.getCertificateInfo(testCertificate)

        // Verify the info
        assertNotNull(certInfo)
        assertTrue(certInfo.containsKey("subjectDN"))
        assertTrue(certInfo.containsKey("issuerDN"))
        assertTrue(certInfo.containsKey("version"))
        assertTrue(certInfo.containsKey("serialNumber"))
        assertTrue(certInfo.containsKey("validFrom"))
        assertTrue(certInfo.containsKey("validUntil"))
        assertTrue(certInfo.containsKey("signatureAlgorithm"))
        assertTrue(certInfo.containsKey("publicKeyAlgorithm"))
    }

    @Test
    fun `test verify hostname exact match`() {
        assertTrue(validator.verifyHostname(testCertificate, "example.com"))
    }

    @Test
    fun `test verify hostname wildcard match`() {
        // RFC 6125: '*.test.example.com' matches only one subdomain
        assertTrue(validator.verifyHostname(multiDomainCertificate, "sub.test.example.com"))
        // Should not match multi-level subdomain
        assertFalse(validator.verifyHostname(multiDomainCertificate, "sub.sub.test.example.com"))
        // Should not match base domain
        assertFalse(validator.verifyHostname(multiDomainCertificate, "test.example.com"))
    }

    @Test
    fun `test verify hostname no match`() {
        assertFalse(validator.verifyHostname(testCertificate, "other.com"))
    }

    @Test
    fun `test verify hostname with subject alt names`() {
        assertTrue(validator.verifyHostname(testCertificate, "alt.example.com"))
    }

    @Test
    fun `test verify hostname with IDN`() {
        // Output certificate SAN extension content
        println("\n========== IDN Test Start ==========")
        val sans = multiDomainCertificate.subjectAlternativeNames
        if (sans != null) {
            println("Certificate SubjectAlternativeNames:")
            for (san in sans) {
                val type = san[0] as Int
                val value = san[1] as String
                println("  Type: $type, Value: $value")
            }
        }

        // Get IDN domain from certificate
        val certIdnValue = extractCertificateIDN(sans)
        println("Certificate IDN domain: $certIdnValue")

        if (certIdnValue != null) {
            // Test direct Punycode format matching
            println("\nTest 1: Direct validation using certificate Punycode")
            val punycodeResult = validator.verifyHostname(multiDomainCertificate, certIdnValue)
            println("Punycode direct match result: $punycodeResult")
            assertTrue(punycodeResult, "Should match using certificate Punycode domain")

            // Convert Punycode to Unicode and test
            val unicodeHostname = IDN.toUnicode(certIdnValue)
            println("\nTest 2: Validate after converting certificate Punycode to Unicode")
            println("Punycode to Unicode: $unicodeHostname")

            val unicodeResult = validator.verifyHostname(multiDomainCertificate, unicodeHostname)
            println("Unicode format match result: $unicodeResult")
            assertTrue(unicodeResult, "Should match using converted Unicode domain")
        } else {
            fail("No IDN domain found in certificate")
        }

        println("========== IDN Test End ==========\n")
    }

    private fun extractCertificateIDN(sans: Collection<List<*>>?): String? {
        if (sans == null) return null

        for (san in sans) {
            val type = san[0] as Int
            val value = san[1] as String

            // DNS type = 2, and is Punycode format IDN
            if (type == 2 && value.contains("xn--")) {
                return value
            }
        }
        return null
    }

    @Test
    fun `test verify hostname with IP address`() {
        // The ipCertificate is generated with 192.168.1.1 and 10.0.0.1 in SAN
        assertTrue(validator.verifyHostname(ipCertificate, "192.168.1.1"))
        assertTrue(validator.verifyHostname(ipCertificate, "10.0.0.1"))
        // Non-matching IP address
        assertFalse(validator.verifyHostname(ipCertificate, "192.168.1.2"))
        // IP address should not match DNS name (testCertificate does not have IP in SAN)
        assertFalse(validator.verifyHostname(testCertificate, "192.168.1.1"))
    }

    @Test
    fun `test verify hostname edge cases`() {
        val caCertificate = certGenerator.generateCACertificate()
        val caKey = keyPair.private
        val wildcardKeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val wildcardCert = certGenerator.generateLeafCertificate(
            subject = "CN=*.example.com, O=Test Organization, C=US",
            issuerCert = caCertificate,
            issuerKey = caKey,
            subjectKeyPair = wildcardKeyPair,
            dnsNames = arrayOf("*.example.com"),
            ipAddresses = null
        )
        // Should not match base domain or domain with trailing dot
        assertFalse(validator.verifyHostname(wildcardCert, "example.com."))
        assertFalse(validator.verifyHostname(wildcardCert, "example.com"))
        // Case insensitivity test
        assertTrue(validator.verifyHostname(wildcardCert, "SUB.example.com"))
        // Should match only one subdomain
        assertTrue(validator.verifyHostname(wildcardCert, "foo.example.com"))
        // Should not match multi-level subdomain
        assertFalse(validator.verifyHostname(wildcardCert, "bar.foo.example.com"))
        // Empty hostname should not match
        assertFalse(validator.verifyHostname(wildcardCert, ""))
    }
} 