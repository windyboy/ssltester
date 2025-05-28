package org.example.cert

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.example.config.SSLTestConfig
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import kotlin.test.*
import io.mockk.*
import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import org.junit.jupiter.api.AfterEach

class CertificateRevocationCheckerTest {

    @AfterEach
    fun tearDown() {
        clearAllMocks() // Clears all MockK mocks after each test
    }

    companion object {
        private lateinit var certGenerator: TestCertificateGenerator
        
        // Root CA
        private lateinit var rootCaKeyPair: KeyPair
        private lateinit var rootCaCert: X509Certificate

        // Intermediate CA (signs OCSP responder and subject's issuer)
        private lateinit var intermediateCaKeyPair: KeyPair
        private lateinit var intermediateCaCert: X509Certificate
        
        // Subject's Issuer
        private lateinit var subjectIssuerKeyPair: KeyPair
        private lateinit var subjectIssuerCert: X509Certificate

        // Subject Certificate
        private lateinit var subjectKeyPair: KeyPair
        private lateinit var subjectCert: X509Certificate
        
        // OCSP Responder (signed by subject's issuer)
        private lateinit var ocspResponderKeyPair: KeyPair
        private lateinit var ocspResponderCert: X509Certificate         // With OCSP EKU
        private lateinit var ocspResponderCertNoEKU: X509Certificate    // Without OCSP EKU

        // Untrusted OCSP Responder (signed by root CA directly, not by subject's issuer)
        private lateinit var untrustedOcspResponderKeyPair: KeyPair
        private lateinit var untrustedOcspResponderCert: X509Certificate 


        @BeforeAll
        @JvmStatic
        fun suiteSetup() {
            Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) ?: Security.addProvider(BouncyCastleProvider())
            certGenerator = TestCertificateGenerator()

            // Root CA
            rootCaKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            rootCaCert = certGenerator.generateCACertificate(rootCaKeyPair, "CN=Test Root CA")

            // Intermediate CA (signed by Root CA) - this will be the issuer of subjectIssuerCert and ocspResponderCert
            intermediateCaKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            intermediateCaCert = certGenerator.generateLeafCertificate(
                subject = "CN=Test Intermediate CA",
                issuerCert = rootCaCert,
                issuerKey = rootCaKeyPair.private,
                subjectKeyPair = intermediateCaKeyPair,
                isCA = true // BasicConstraints(true)
            )
            
            // Subject's Issuer (signed by Intermediate CA)
            subjectIssuerKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            subjectIssuerCert = certGenerator.generateLeafCertificate(
                subject = "CN=Test Subject Issuer CA",
                issuerCert = intermediateCaCert,
                issuerKey = intermediateCaKeyPair.private,
                subjectKeyPair = subjectIssuerKeyPair,
                isCA = true
            )

            // Subject Certificate (signed by Subject's Issuer)
            subjectKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            subjectCert = certGenerator.generateLeafCertificate(
                subject = "CN=Test Subject",
                issuerCert = subjectIssuerCert,
                issuerKey = subjectIssuerKeyPair.private,
                subjectKeyPair = subjectKeyPair
            )
            
            // OCSP Responder Certificate (signed by Subject's Issuer, with EKU)
            ocspResponderKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            ocspResponderCert = certGenerator.generateLeafCertificate(
                subject = "CN=Test OCSP Responder",
                issuerCert = subjectIssuerCert, // Signed by the subject's issuer
                issuerKey = subjectIssuerKeyPair.private,
                subjectKeyPair = ocspResponderKeyPair,
                extendedKeyUsages = listOf(KeyPurposeId.id_kp_OCSPSigning)
            )

            // OCSP Responder Certificate (signed by Subject's Issuer, WITHOUT EKU)
            ocspResponderCertNoEKU = certGenerator.generateLeafCertificate(
                subject = "CN=Test OCSP Responder No EKU",
                issuerCert = subjectIssuerCert, // Signed by the subject's issuer
                issuerKey = subjectIssuerKeyPair.private,
                subjectKeyPair = ocspResponderKeyPair, // Can reuse keypair for simplicity here
                extendedKeyUsages = emptyList() // No EKU
            )
            
            // Untrusted OCSP Responder Certificate (signed by Root CA directly)
            untrustedOcspResponderKeyPair = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME).apply { initialize(2048) }.generateKeyPair()
            untrustedOcspResponderCert = certGenerator.generateLeafCertificate(
                subject = "CN=Untrusted Test OCSP Responder",
                issuerCert = rootCaCert, // Signed by Root CA, not subject's issuer
                issuerKey = rootCaKeyPair.private,
                subjectKeyPair = untrustedOcspResponderKeyPair,
                extendedKeyUsages = listOf(KeyPurposeId.id_kp_OCSPSigning)
            )
        }
    }
    
    private fun createChecker(
        checkOCSP: Boolean = true, 
        checkCRL: Boolean = true, 
        failOnError: Boolean = true,
        httpClient: HttpClient = HttpClient.newHttpClient() // Allow passing a custom client for mocking
    ): CertificateRevocationChecker {
        return CertificateRevocationChecker(
            checkOCSP = checkOCSP, 
            checkCRL = checkCRL, 
            failOnError = failOnError,
            httpClient = httpClient
        )
    }

    private fun createMockOcspResponseBytes(
        subjectCertificate: X509Certificate,
        issuerCertificate: X509Certificate,
        certificateStatus: CertificateStatus?, // Null for GOOD, or RevokedStatus/UnknownStatus
        responderSignerKeyPair: KeyPair,
        responderCertificateForEmbedding: X509Certificate?, // Certificate to embed in the response
        ocspRespStatus: Int = OCSPRespBuilder.SUCCESSFUL,
        responseCertIdOverride: CertificateID? = null // For testing mismatch
    ): ByteArray {
        val basicBuilder = BasicOCSPRespBuilder(
            SubjectPublicKeyInfo.getInstance(responderSignerKeyPair.public.encoded), // Default to key hash based ResponderID
            JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build().get(CertificateID.HASH_SHA1)
        )

        // Can also use: BasicOCSPRespBuilder(X509CertificateHolder(responderCertificateForEmbedding.encoded).subject, ...) for name based ResponderID

        val targetCertId = responseCertIdOverride ?: CertificateID(
            JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build().get(CertificateID.HASH_SHA1),
            X509CertificateHolder(issuerCertificate.encoded),
            subjectCertificate.serialNumber
        )
        
        basicBuilder.addResponse(targetCertId, certificateStatus ?: CertificateStatus.GOOD, Date(), null) // thisUpdate, nextUpdate (optional)

        responderCertificateForEmbedding?.let {
            basicBuilder.addCertificate(X509CertificateHolder(it.encoded))
        }
        
        val basicOcspResp = basicBuilder.build(
            JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(responderSignerKeyPair.private),
            if (responderCertificateForEmbedding != null) arrayOf(X509CertificateHolder(responderCertificateForEmbedding.encoded)) else null,
            Date() // producedAt
        )

        val ocspRespBuilder = OCSPRespBuilder()
        if (ocspRespStatus != OCSPRespBuilder.SUCCESSFUL) {
             return ocspRespBuilder.build(ocspRespStatus, null) // No response object for failure status
        }
        return ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOcspResp)
    }


    // --- Tests for getOCSPUrl ---
    @Test
    fun `getOCSPUrl returns URL from valid AIA extension`() {
        val expectedOcspUrl = "http://ocsp.example.com"
        val leafCert = certGenerator.generateLeafCertificate(
            subject = "CN=AIA OCSP Test",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            ocspServerUri = expectedOcspUrl
        )
        val checker = createChecker()
        val ocspUrl = checker.getOCSPUrl(leafCert)
        assertEquals(expectedOcspUrl, ocspUrl)
    }

    @Test
    fun `getOCSPUrl returns null if AIA has only caIssuers URI`() {
        val leafCert = certGenerator.generateLeafCertificate(
            subject = "CN=AIA CAIssuers Test",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            caIssuersUri = "http://caissuer.example.com/cert.der"
        )
        val checker = createChecker()
        val ocspUrl = checker.getOCSPUrl(leafCert)
        assertNull(ocspUrl)
    }
    
    @Test
    fun `getOCSPUrl returns primary OCSP URL if multiple access methods exist`() {
        val expectedOcspUrl = "http://ocsp.primary.com"
        val leafCert = certGenerator.generateLeafCertificate(
            subject = "CN=AIA Multi-Method Test",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            ocspServerUri = expectedOcspUrl, // This should be found
            caIssuersUri = "http://caissuer.example.com/cert.der"
        )
        val checker = createChecker()
        val ocspUrl = checker.getOCSPUrl(leafCert)
        assertEquals(expectedOcspUrl, ocspUrl)
    }


    @Test
    fun `getOCSPUrl returns null if no AIA extension present`() {
        val leafCert = certGenerator.generateLeafCertificate("CN=No AIA Cert", caCertificate, caKeyPair.private)
        val checker = createChecker()
        val ocspUrl = checker.getOCSPUrl(leafCert)
        assertNull(ocspUrl)
    }

    // --- Tests for getCRLUrls ---
    @Test
    fun `getCRLUrls returns URLs from valid CRLDP extension`() {
        val expectedCrlUrls = listOf("http://crl1.example.com/crl.crl", "http://crl2.example.com/crl.crl")
        val leafCert = certGenerator.generateLeafCertificate(
            subject = "CN=CRLDP Test",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            crlUris = expectedCrlUrls
        )
        val checker = createChecker()
        val crlUrls = checker.getCRLUrls(leafCert)
        assertEquals(expectedCrlUrls.sorted(), crlUrls.sorted())
    }

    @Test
    fun `getCRLUrls returns empty list if CRLDP has no URIs`() {
        // TestCertificateGenerator's addCRLDistributionPointsExtension handles empty list gracefully (adds no extension)
        // To test an *empty* DistributionPoint list, we'd need a more specific generator method.
        // For now, this tests the case where the crlUris parameter to the generator is empty or null.
        val leafCertWithEmptyCrlList = certGenerator.generateLeafCertificate(
            subject = "CN=Empty CRLDP URIs",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            crlUris = emptyList() // This results in no CRLDP extension being added
        )
        val checker = createChecker()
        var crlUrls = checker.getCRLUrls(leafCertWithEmptyCrlList)
        assertTrue(crlUrls.isEmpty(), "CRL URLs should be empty when CRL URI list is empty for generator")

        val leafCertWithNullCrlList = certGenerator.generateLeafCertificate(
            subject = "CN=Null CRLDP URIs",
            issuerCert = caCertificate,
            issuerKey = caKeyPair.private,
            crlUris = null // This also results in no CRLDP extension
        )
        crlUrls = checker.getCRLUrls(leafCertWithNullCrlList)
        assertTrue(crlUrls.isEmpty(), "CRL URLs should be empty when CRL URI list is null for generator")
    }

    @Test
    fun `getCRLUrls returns empty list if no CRLDP extension present`() {
        val leafCert = certGenerator.generateLeafCertificate("CN=No CRLDP Cert", caCertificate, caKeyPair.private)
        val checker = createChecker()
        val crlUrls = checker.getCRLUrls(leafCert)
        assertTrue(crlUrls.isEmpty())
    }

    // --- Tests for generateOCSPRequest ---
    @Test
    fun `generateOCSPRequest successfully creates request`() {
        val checker = createChecker()
        val requestBytes = checker.generateOCSPRequest(subjectCert, subjectIssuerCert) // Use subjectCert and its issuer

        assertNotNull(requestBytes)
        assertTrue(requestBytes.isNotEmpty())

        val ocspReq = OCSPReq(requestBytes)
        assertNotNull(ocspReq)
        assertEquals(1, ocspReq.requestList.size)
        
        val request = ocspReq.requestList[0]
        val actualCertId = request.reqCert

        // Use the same method as in the checker to generate the expected CertID
        val expectedCertId = checker.generateCertificateID(subjectCert, subjectIssuerCert)

        assertContentEquals(expectedCertId.issuerNameHash, actualCertId.issuerNameHash, "Issuer Name Hash mismatch")
        assertContentEquals(expectedCertId.issuerKeyHash, actualCertId.issuerKeyHash, "Issuer Key Hash mismatch")
        assertEquals(expectedCertId.serialNumber, actualCertId.serialNumber, "Serial Number mismatch")
        assertEquals(expectedCertId.hashAlgorithm.algorithm, actualCertId.hashAlgorithm.algorithm, "Hash Algorithm OID mismatch")
    }

    @Test
    fun `generateOCSPRequest throws CertificateException if issuer is null`() {
        val checker = createChecker()
        val exception = assertThrows<CertificateException>("Should throw CertificateException for null issuer") {
            checker.generateOCSPRequest(subjectCert, null) // Use subjectCert
        }
        assertTrue(exception.message?.contains("Issuer certificate is required") == true)
    }

    // --- Tests for validateOCSPResponse (which calls verifyOCSPResponseSignature) ---

    @Test
    fun `validateOCSPResponse accepts valid GOOD response`() {
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            ocspResponderKeyPair, ocspResponderCert
        )
        assertDoesNotThrow("Valid GOOD response should not throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
    }

    @Test
    fun `validateOCSPResponse throws for valid REVOKED response`() {
        val checker = createChecker(failOnError = true)
        val revokedStatus = RevokedStatus(Date(), CRLReason.privilegeWithdrawn)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, revokedStatus,
            ocspResponderKeyPair, ocspResponderCert
        )
        val exception = assertThrows<CertificateException>("REVOKED response should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("Certificate is REVOKED") == true)
    }

    @Test
    fun `validateOCSPResponse throws for valid UNKNOWN response`() {
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, UnknownStatus.getInstance(),
            ocspResponderKeyPair, ocspResponderCert
        )
        val exception = assertThrows<CertificateException>("UNKNOWN response should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("OCSP status is UNKNOWN") == true)
    }

    @Test
    fun `validateOCSPResponse throws for response with invalid signature`() {
        val checker = createChecker(failOnError = true)
        val wrongKeyPair = KeyPairGenerator.getInstance("RSA").apply{initialize(2048)}.generateKeyPair()
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            wrongKeyPair, ocspResponderCert // Signed with wrong key
        )
        val exception = assertThrows<CertificateException>("Invalid signature should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("OCSP response signature validation failed") == true)
    }

    @Test
    fun `validateOCSPResponse accepts response from signer without OCSP EKU (logs warning)`() {
        // Current behavior is to log a warning but not fail if failOnError=true for this specific case.
        // The check is inside verifyOCSPResponseSignature, which returns true if only EKU is missing.
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            ocspResponderKeyPair, ocspResponderCertNoEKU // Responder cert without OCSP EKU
        )
        // This will pass because the signature is valid and the cert is issued by trusted issuer.
        // The EKU check in verifyOCSPResponseSignature only logs a warning.
        assertDoesNotThrow("Response from signer without OCSP EKU should be accepted (with warning)") {
             checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
    }

    @Test
    fun `validateOCSPResponse accepts response from untrusted responder (conditionally)`() {
        // "Untrusted" here means not directly signed by subject's issuer.
        // verifyOCSPResponseSignature logs a warning but returns true if signature is valid.
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            untrustedOcspResponderKeyPair, untrustedOcspResponderCert // Signed by a different CA
        )
         // This will pass if signature is valid, but logs a warning about trust.
        assertDoesNotThrow("Response from responder not directly trusted by subject's issuer should be accepted (with warning)") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
    }
    
    @Test
    fun `validateOCSPResponse throws if responder certificate is missing from response`() {
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            ocspResponderKeyPair, null // Responder cert NOT included in response
        )
        val exception = assertThrows<CertificateException>("Missing responder cert should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("OCSP response signature validation failed") == true, 
            "Exception message should indicate signature validation failure due to missing cert. Actual: ${exception.message}")
    }

    @Test
    fun `validateOCSPResponse throws for CertID mismatch`() {
        val checker = createChecker(failOnError = true)
        // Create a CertificateID for a different certificate (e.g., the issuer cert itself)
        val wrongCertId = checker.generateCertificateID(subjectIssuerCert, intermediateCaCert)
        
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            ocspResponderKeyPair, ocspResponderCert,
            responseCertIdOverride = wrongCertId
        )
        val exception = assertThrows<CertificateException>("CertID mismatch should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("OCSP response is for a different certificate") == true)
    }
    
    @Test
    fun `validateOCSPResponse throws if OCSPResp status is not SUCCESSFUL`() {
        val checker = createChecker(failOnError = true)
        val mockResponse = createMockOcspResponseBytes(
            subjectCert, subjectIssuerCert, CertificateStatus.GOOD,
            ocspResponderKeyPair, ocspResponderCert,
            ocspRespStatus = OCSPRespBuilder.MALFORMED_REQUEST
        )
        val exception = assertThrows<CertificateException>("Non-SUCCESSFUL OCSPResp status should throw") {
            checker.validateOCSPResponse(mockResponse, subjectCert, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("OCSP response unsuccessful. Status: ${OCSPRespBuilder.MALFORMED_REQUEST}") == true)
    }

    // --- Helper function for creating CRLs ---
    private fun createTestCRL(
        revokedEntries: List<Pair<BigInteger, Date>>, // Serial number and revocation date
        issuerKeyPair: KeyPair,
        issuerCert: X509Certificate,
        nextUpdateHours: Long = 24
    ): ByteArray {
        val crlBuilder = X509v2CRLBuilder(X500Name(issuerCert.subjectX500Principal.name), Date())
        crlBuilder.setNextUpdate(Date(System.currentTimeMillis() + nextUpdateHours * 60 * 60 * 1000))

        val extUtils = JcaX509ExtensionUtils()
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert.publicKey))

        for ((serialNumber, revocationDate) in revokedEntries) {
            crlBuilder.addCRLEntry(serialNumber, revocationDate, CRLReason.unspecified)
        }

        val contentSigner = JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKeyPair.private)
        return crlBuilder.build(contentSigner).encoded
    }

    // --- Tests for parseCRL ---
    @Test
    fun `parseCRL successfully parses valid CRL bytes`() {
        val checker = createChecker()
        val crlBytes = createTestCRL(emptyList(), subjectIssuerKeyPair, subjectIssuerCert)
        val crl = checker.parseCRL(crlBytes)
        assertNotNull(crl)
        assertEquals(subjectIssuerCert.subjectX500Principal.name, crl.issuerX500Principal.name)
    }

    @Test
    fun `parseCRL throws CRLException for malformed CRL bytes`() {
        val checker = createChecker()
        val malformedBytes = "this is not a valid CRL".toByteArray()
        assertThrows<CRLException>("Malformed CRL should throw CRLException") {
            checker.parseCRL(malformedBytes)
        }
    }

    // --- Tests for checkCRL ---
    // MockK setup will be conceptual here.
    // For these tests to run, MockK needs to be in the project.
    // And CertificateRevocationChecker needs to allow HttpClient injection or use a static/object mock.
    // For simplicity, I'll assume direct mocking of the client instance if possible,
    // otherwise these tests highlight the interaction points.

    @Test
    fun `checkCRL throws CertificateException if certificate is revoked`() {
        val testCrlUri = "http://crl.example.com/ca.crl"
        val revokedSubjectCert = certGenerator.generateLeafCertificate(
            subject = "CN=Revoked Subject",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = listOf(testCrlUri)
        )

        val crlBytes = createTestCRL(
            listOf(revokedSubjectCert.serialNumber to Date()),
            subjectIssuerKeyPair,
            subjectIssuerCert
        )

        val mockHttpClient = mockk<HttpClient>()
        val mockHttpResponse = mockk<HttpResponse<ByteArray>>()

        every { mockHttpResponse.statusCode() } returns 200
        every { mockHttpResponse.body() } returns crlBytes
        every { mockHttpClient.send(any(), any<HttpResponse.BodyHandler<ByteArray>>()) } returns mockHttpResponse
        
        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false, failOnError = true) // Focus on CRL

        val exception = assertThrows<CertificateException> {
            // Test through the public API to ensure failOnError is applied from the constructor
            checker.checkRevocation(revokedSubjectCert, subjectIssuerCert) 
        }
        assertTrue(exception.message?.contains("Certificate is revoked according to CRL") == true)
        
        verify(exactly = 1) { mockHttpClient.send(match { it.uri() == URI(testCrlUri) }, any()) }
    }

    @Test
    fun `checkCRL does not throw if certificate is not on CRL`() {
        val testCrlUri = "http://crl.example.com/ca.crl"
        val nonRevokedSubjectCert = certGenerator.generateLeafCertificate(
            subject = "CN=Non-Revoked Subject",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = listOf(testCrlUri)
        )
        val crlBytes = createTestCRL(emptyList(), subjectIssuerKeyPair, subjectIssuerCert) // Empty CRL

        val mockHttpClient = mockk<HttpClient>()
        val mockHttpResponse = mockk<HttpResponse<ByteArray>>()

        every { mockHttpResponse.statusCode() } returns 200
        every { mockHttpResponse.body() } returns crlBytes
        every { mockHttpClient.send(any(), any<HttpResponse.BodyHandler<ByteArray>>()) } returns mockHttpResponse

        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false, failOnError = true)
        
        assertDoesNotThrow {
             // Test through the public API to ensure failOnError logic is engaged if needed
            checker.checkRevocation(nonRevokedSubjectCert, subjectIssuerCert)
        }
        verify(exactly = 1) { mockHttpClient.send(match { it.uri() == URI(testCrlUri) }, any()) }
    }

    @Test
    fun `checkCRL does not throw or fetch if no CRL URLs in certificate`() {
        val certWithoutCrlDP = certGenerator.generateLeafCertificate(
            subject = "CN=No CRLDP Subject",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = null // No CRL URIs
        )
        val mockHttpClient = mockk<HttpClient>() // Mock to verify it's not called
        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false)
        
        assertDoesNotThrow {
            checker.checkRevocation(certWithoutCrlDP, subjectIssuerCert)
        }
        verify(exactly = 0) { mockHttpClient.send(any(), any()) } // Verify client was not called
    }

    @Test
    fun `checkCRL throws CertificateException if CRL fetch fails (HTTP error) and failOnError is true`() {
        val testCrlUri = "http://crl.example.com/ca.crl"
        val subjectForHttpError = certGenerator.generateLeafCertificate(
            subject = "CN=CRL HTTP Error",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = listOf(testCrlUri)
        )

        val mockHttpClient = mockk<HttpClient>()
        // Simulate send throwing an IOException
        every { mockHttpClient.send(any(), any<HttpResponse.BodyHandler<ByteArray>>()) } throws IOException("Simulated HTTP fetch error")
        
        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false, failOnError = true)

        val exception = assertThrows<CertificateException>("Should throw due to HTTP error and failOnError=true") {
            checker.checkRevocation(subjectForHttpError, subjectIssuerCert)
        }
        assertTrue(exception.message?.contains("CRL check failed") == true && exception.cause is IOException)
        verify(exactly = 1) { mockHttpClient.send(match { it.uri() == URI(testCrlUri) }, any()) }
    }
    
    @Test
    fun `checkCRL continues if one CRL fetch fails but another succeeds (failOnError=false for overall check)`() {
        val crlUri1 = "http://crl1.example.com/crl.crl" // This will fail
        val crlUri2 = "http://crl2.example.com/crl.crl" // This will succeed (cert not on it)
        
        val subjectCert = certGenerator.generateLeafCertificate(
            subject = "CN=Multi CRL Test",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = listOf(crlUri1, crlUri2)
        )

        val mockHttpClient = mockk<HttpClient>()
        val goodHttpResponse = mockk<HttpResponse<ByteArray>>(relaxed = true) // relaxed to avoid mocking all methods

        val goodCrlBytes = createTestCRL(emptyList(), subjectIssuerKeyPair, subjectIssuerCert)

        every { goodHttpResponse.statusCode() } returns 200
        every { goodHttpResponse.body() } returns goodCrlBytes
        
        // Mock behavior for specific URIs
        every { mockHttpClient.send(match { it.uri().toString() == crlUri1 }, any<HttpResponse.BodyHandler<ByteArray>>()) } throws IOException("Simulated HTTP error for crl1")
        every { mockHttpClient.send(match { it.uri().toString() == crlUri2 }, any<HttpResponse.BodyHandler<ByteArray>>()) } returns goodHttpResponse
        
        // failOnError = false at constructor means individual CRL error won't stop checkRevocation if other checks pass
        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false, failOnError = false) 

        assertDoesNotThrow("Should not throw if one CRL fails but another succeeds and cert not revoked, and failOnError=false for overall check") {
            checker.checkRevocation(subjectCert, subjectIssuerCert)
        }
        verify(exactly = 1) { mockHttpClient.send(match { it.uri().toString() == crlUri1 }, any()) }
        verify(exactly = 1) { mockHttpClient.send(match { it.uri().toString() == crlUri2 }, any()) }
    }


    @Test
    fun `checkCRL throws CertificateException if CRL from URL is malformed and failOnError is true`() {
        val testCrlUri = "http://crl.example.com/ca.crl"
        val subjectForMalformedCrl = certGenerator.generateLeafCertificate(
            subject = "CN=Malformed CRL Fetch",
            issuerCert = subjectIssuerCert,
            issuerKey = subjectIssuerKeyPair.private,
            crlUris = listOf(testCrlUri)
        )
        val malformedCrlBytes = "this is not a valid CRL".toByteArray()

        val mockHttpClient = mockk<HttpClient>()
        val mockHttpResponse = mockk<HttpResponse<ByteArray>>()

        every { mockHttpResponse.statusCode() } returns 200
        every { mockHttpResponse.body() } returns malformedCrlBytes
        every { mockHttpClient.send(any(), any<HttpResponse.BodyHandler<ByteArray>>()) } returns mockHttpResponse
        
        val checker = createChecker(httpClient = mockHttpClient, checkOCSP = false, failOnError = true)

        val exception = assertThrows<CertificateException>("Should throw due to malformed CRL and failOnError=true") {
           checker.checkRevocation(subjectForMalformedCrl, subjectIssuerCert)
        }
        assertTrue(exception.cause is CRLException || exception.message!!.contains("Failed to parse CRL"))
        verify(exactly = 1) { mockHttpClient.send(match { it.uri() == URI(testCrlUri) }, any()) }
    }
}
