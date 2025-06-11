package org.example.cert

import kotlin.test.*
import org.bouncycastle.asn1.DEROctetString
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.example.config.SSLTestConfig
import java.net.InetAddress

class CertificateValidatorTest {
    private lateinit var tempDir: File
    private var config: SSLTestConfig? = null
    private var validator: CertificateValidator? = null
    private lateinit var validKeyPair: KeyPair
    private lateinit var validCertificate: X509Certificate
    private lateinit var expiredCertificate: X509Certificate
    private lateinit var notYetValidCertificate: X509Certificate
    private lateinit var selfSignedCertificate: X509Certificate
    private lateinit var intermediateCertificate: X509Certificate
    private lateinit var leafCertificate: X509Certificate
    private lateinit var rootCertificate: X509Certificate

    @BeforeTest
    fun setup() {
        tempDir = createTempDir()
        // Generate test certificates
        validKeyPair = generateKeyPair()
        validCertificate = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("example.com", "*.example.com")
        )

        expiredCertificate = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=expired.example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(365)),
            validUntil = Instant.now().minus(Duration.ofDays(1)),
            domains = listOf("expired.example.com")
        )

        notYetValidCertificate = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=future.example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().plus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("future.example.com")
        )

        selfSignedCertificate = generateSelfSignedCertificate(
            keyPair = validKeyPair,
            subject = "CN=self-signed.example.com",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("self-signed.example.com")
        )

        // Create a chain: root CA -> intermediate CA -> leaf certificate
        val rootKeyPair = generateKeyPair()
        val intermediateKeyPair = generateKeyPair()
        val leafKeyPair = generateKeyPair()

        rootCertificate = generateSelfSignedCertificate(
            keyPair = rootKeyPair,
            subject = "CN=Root CA",
            validFrom = Instant.now().minus(Duration.ofDays(10)),
            validUntil = Instant.now().plus(Duration.ofDays(3650)),
            isCA = true
        )

        intermediateCertificate = generateCertificate(
            keyPair = intermediateKeyPair,
            subject = "CN=Intermediate CA",
            issuer = "CN=Root CA",
            validFrom = Instant.now().minus(Duration.ofDays(5)),
            validUntil = Instant.now().plus(Duration.ofDays(1825)),
            isCA = true,
            issuerKeyPair = rootKeyPair
        )

        leafCertificate = generateCertificate(
            keyPair = leafKeyPair,
            subject = "CN=leaf.example.com",
            issuer = "CN=Intermediate CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("leaf.example.com", "www.leaf.example.com"),
            issuerKeyPair = intermediateKeyPair
        )

        // Create a test keystore with the root certificate
        val keystoreFile = File(tempDir, "test-truststore.jks")
        val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
        keystore.load(null, null)
        keystore.setCertificateEntry("root-ca", rootCertificate)
        keystore.setCertificateEntry("self-signed", selfSignedCertificate)

        FileOutputStream(keystoreFile).use { fos ->
            keystore.store(fos, "password".toCharArray())
        }

        // Configure the validator with a real SSLTestConfig instance
        val testConfig = SSLTestConfig()
        testConfig.keystoreFile = keystoreFile
        testConfig.keystorePassword = "password"
        config = testConfig
        validator = CertificateValidator(config!!)
    }

    @Test
    fun `validateCertificateChain should validate certificate chain`() {
        val result = validator!!.validateCertificateChain(
            arrayOf(leafCertificate, intermediateCertificate),
            "leaf.example.com"
        )
        assertEquals(2, result.size)
        assertSame(leafCertificate, result[0])
        assertSame(intermediateCertificate, result[1])
    }

    @Test
    fun `validateCertificateChain should throw exception for hostname mismatch`() {
        val exception = assertFailsWith<CertificateException> {
            validator!!.validateCertificateChain(
                arrayOf(leafCertificate, intermediateCertificate),
                "wrong.example.com"
            )
        }
        assertTrue(exception.message?.contains("Hostname verification failed") == true)
    }

    @Test
    fun `verifyHostname should match exact hostname`() {
        val cert = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=exact.example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("exact.example.com")
        )

        assertTrue(validator!!.verifyHostname(cert, "exact.example.com"))
        assertFalse(validator!!.verifyHostname(cert, "other.example.com"))
    }

    @Test
    fun `verifyHostname should match wildcard hostname`() {
        val cert = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=*.example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("*.example.com")
        )

        assertTrue(validator!!.verifyHostname(cert, "sub.example.com"))
        assertTrue(validator!!.verifyHostname(cert, "test.example.com"))
        assertFalse(validator!!.verifyHostname(cert, "example.com"))
        assertFalse(validator!!.verifyHostname(cert, "sub.sub.example.com"))
    }

    @Test
    fun `verifyHostname should match IP address`() {
        val cert = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=192.168.1.1",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            ipAddresses = listOf("192.168.1.1")
        )

        // Get the IP address from the certificate's SAN extension
        val sans = cert.getSubjectAlternativeNames()
        println("All SANs: $sans")
        val ipSan = sans?.find { it[0] == 7 }
        println("IP SAN: $ipSan")
        println("IP SAN type: ${ipSan?.get(1)?.javaClass?.name}")
        println("IP SAN value: ${ipSan?.get(1)}")

        assertTrue(validator!!.verifyHostname(cert, "192.168.1.1"))
        assertFalse(validator!!.verifyHostname(cert, "192.168.1.2"))
    }

    @Test
    fun `verifyHostname should match Common Name when no SAN present`() {
        val cert = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=cn.example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365))
        )

        assertTrue(validator!!.verifyHostname(cert, "cn.example.com"))
        assertFalse(validator!!.verifyHostname(cert, "other.example.com"))
    }

    @Test
    fun `verifyHostname should return false for empty hostname`() {
        val cert = generateCertificate(
            keyPair = validKeyPair,
            subject = "CN=example.com",
            issuer = "CN=Test CA",
            validFrom = Instant.now().minus(Duration.ofDays(1)),
            validUntil = Instant.now().plus(Duration.ofDays(365)),
            domains = listOf("example.com")
        )

        assertFalse(validator!!.verifyHostname(cert, ""))
    }

    @Test
    fun `checkClientTrusted should throw exception`() {
        val exception = assertFailsWith<CertificateException> {
            validator!!.checkClientTrusted(arrayOf(validCertificate), "RSA")
        }
        assertEquals("Client certificate validation not supported", exception.message)
    }

    @Test
    fun `checkServerTrusted should throw exception for null chain`() {
        val exception = assertFailsWith<CertificateException> {
            validator!!.checkServerTrusted(null, "RSA")
        }
        assertEquals("Certificate chain is null or empty", exception.message)
    }

    @Test
    fun `checkServerTrusted should throw exception for empty chain`() {
        val exception = assertFailsWith<CertificateException> {
            validator!!.checkServerTrusted(emptyArray(), "RSA")
        }
        assertEquals("Certificate chain is null or empty", exception.message)
    }

    // Helper functions for certificate generation
    private fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        return generator.generateKeyPair()
    }

    private fun generateCertificate(
        keyPair: KeyPair,
        subject: String,
        issuer: String,
        validFrom: Instant,
        validUntil: Instant,
        domains: List<String> = emptyList(),
        ipAddresses: List<String> = emptyList(),
        isCA: Boolean = false,
        issuerKeyPair: KeyPair? = null
    ): X509Certificate {
        val subjectDN = X500Name(subject)
        val issuerDN = X500Name(issuer)
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(issuerKeyPair?.private ?: keyPair.private)

        val builder = JcaX509v3CertificateBuilder(
            issuerDN,
            serial,
            Date.from(validFrom),
            Date.from(validUntil),
            subjectDN,
            keyPair.public
        )

        // Add Basic Constraints extension
        builder.addExtension(
            Extension.basicConstraints,
            true,
            BasicConstraints(isCA)
        )

        // Add Subject Alternative Names
        if (domains.isNotEmpty() || ipAddresses.isNotEmpty()) {
            val sans = mutableListOf<GeneralName>()
            domains.forEach { sans.add(GeneralName(GeneralName.dNSName, it)) }
            ipAddresses.forEach { ip ->
                val ipBytes = InetAddress.getByName(ip).address
                println("Creating IP SAN for $ip with bytes: ${ipBytes.joinToString()}")
                val derOctetString = DEROctetString(ipBytes)
                println("DEROctetString: $derOctetString")
                val generalName = GeneralName(GeneralName.iPAddress, derOctetString)
                println("GeneralName: $generalName")
                sans.add(generalName)
            }
            builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(sans.toTypedArray())
            )
        }

        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun generateSelfSignedCertificate(
        keyPair: KeyPair,
        subject: String,
        validFrom: Instant,
        validUntil: Instant,
        domains: List<String> = emptyList(),
        ipAddresses: List<String> = emptyList(),
        isCA: Boolean = false
    ): X509Certificate {
        return generateCertificate(
            keyPair = keyPair,
            subject = subject,
            issuer = subject,
            validFrom = validFrom,
            validUntil = validUntil,
            domains = domains,
            ipAddresses = ipAddresses,
            isCA = isCA,
            issuerKeyPair = keyPair
        )
    }
} 