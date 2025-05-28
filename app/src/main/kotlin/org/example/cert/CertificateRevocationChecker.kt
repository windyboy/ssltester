package org.example.cert

import org.bouncycastle.cert.ocsp.*
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.DistributionPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URI
import java.security.Security
import java.security.Signature
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.cert.CRLException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate
import java.math.BigInteger

class CertificateRevocationChecker(
    private val checkOCSP: Boolean,
    private val checkCRL: Boolean,
    private val failOnError: Boolean = true,
    private val httpClient: HttpClient = HttpClient.newBuilder() // Default client
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()
) {
    private val logger = LoggerFactory.getLogger(CertificateRevocationChecker::class.java)
    // httpClient is now a constructor parameter
    private val x509CertificateConverter = JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
    private val sigAlgNameFinder = DefaultSignatureAlgorithmIdentifierFinder()


    companion object {
        init {
            // Ensure BouncyCastle provider is registered
            Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) ?: Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Checks if a certificate has been revoked using OCSP and/or CRL.
     * @param subjectCertificate The certificate to check.
     * @param issuerCertificate The issuer of the subjectCertificate. Can be null if subjectCertificate is self-signed or issuer is unknown.
     * @throws CertificateException if the certificate is revoked or there's an error checking revocation status (if failOnError is true).
     */
    @Throws(CertificateException::class)
    fun checkRevocation(subjectCertificate: X509Certificate, issuerCertificate: X509Certificate?) {
        if (checkOCSP) {
            try {
                val ocspUrl = getOCSPUrl(subjectCertificate)
                if (ocspUrl == null) {
                    logger.debug("No OCSP responder URL found for certificate: {}", subjectCertificate.subjectX500Principal)
                    // Optionally throw if OCSP is required but no URL is found and failOnError is true
                    return 
                }

                val request = generateOCSPRequest(subjectCertificate, issuerCertificate)
                val responseBytes = sendOCSPRequest(ocspUrl, request)
                validateOCSPResponse(responseBytes, subjectCertificate, issuerCertificate)
            } catch (e: Exception) {
                logger.warn("OCSP check failed for {}: {}", subjectCertificate.subjectX500Principal, e.message, e)
                if (failOnError) {
                    throw CertificateException("OCSP check failed: ${e.message}", e)
                }
            }
        }

        if (checkCRL) {
            try {
                checkCRL(subjectCertificate) // Assuming checkCRL internally handles errors or rethrows
            } catch (e: Exception) {
                logger.warn("CRL check failed for {}: {}", subjectCertificate.subjectX500Principal, e.message, e)
                if (failOnError) {
                    throw CertificateException("CRL check failed: ${e.message}", e)
                }
            }
        }
    }

    /**
     * Generates an OCSP request for the given certificate and its issuer.
     * @param subjectCertificate The certificate to check.
     * @param issuerCertificate The issuer certificate. Required by RFC 5019 for creating CertificateID.
     * @return The generated OCSP request as a byte array.
     * @throws CertificateException if issuerCertificate is null or if request generation fails.
     */
    internal fun generateOCSPRequest(subjectCertificate: X509Certificate, issuerCertificate: X509Certificate?): ByteArray { // Changed to internal for testing
        if (issuerCertificate == null) {
            // While some OCSP responders might accept requests without issuer info (e.g., based on pre-configured certs),
            // RFC 5019 (lightweight OCSP profile) implies issuer info is used for CertificateID.
            // For robust checking, especially with BouncyCastle's CertificateID which requires issuer cert holder and key hash,
            // we need the issuer.
            logger.warn("Issuer certificate not provided for subject: {}. OCSP request might be incomplete or fail.", subjectCertificate.subjectX500Principal)
            // Depending on strictness, could throw here. For now, proceed, but CertificateID might be problematic.
            // Fallback: create CertificateID only with subject info if possible (BC might not allow this directly for SHA1 over issuer's key)
             throw CertificateException("Issuer certificate is required for generating OCSP request for ${subjectCertificate.subjectX500Principal}")
        }

        try {
            val issuerCertHolder = X509CertificateHolder(issuerCertificate.encoded)
            val subjectCertHolder = X509CertificateHolder(subjectCertificate.encoded)

            val digestCalculator = JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build()
                .get(CertificateID.HASH_SHA1) // Algorithm for hashing issuer's name and key

            // Create CertificateID using issuer's information and subject's serial number
            val certId = CertificateID(
                digestCalculator,
                issuerCertHolder, // Issuer's certificate
                subjectCertHolder.serialNumber // Subject's serial number
            )
            
            val requestGenerator = OCSPReqBuilder()
            requestGenerator.addRequest(certId)
            // Optionally add request extensions (e.g., nonce)
            // val extensions = Extensions(arrayOf(Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, DEROctetString(nonceBytes))))
            // requestGenerator.setRequestExtensions(extensions)

            return requestGenerator.build().encoded
        } catch (e: Exception) {
            throw CertificateException("Failed to generate OCSP request for ${subjectCertificate.subjectX500Principal}: ${e.message}", e)
        }
    }

    /**
     * Sends an OCSP request to the specified URL.
     * @param url The OCSP responder URL
     * @param request The OCSP request to send
     * @return The OCSP response as a byte array
     */
    private fun sendOCSPRequest(url: String, request: ByteArray): ByteArray {
        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/ocsp-request")
            .POST(HttpRequest.BodyPublishers.ofByteArray(request))
            .build()

        try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray())
            if (response.statusCode() != 200) {
                throw IOException("OCSP request failed with status: ${response.statusCode()}")
            }
            return response.body()
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("OCSP request interrupted", e)
        }
    }

    /**
     * Validates an OCSP response for a given subject certificate and its issuer.
     * @param responseBytes The raw OCSP response.
     * @param subjectCertificate The certificate whose status is being checked.
     * @param issuerCertificate The issuer of the subject certificate.
     * @throws CertificateException if the response is invalid, indicates revocation, or fails verification.
     */
    @Throws(CertificateException::class)
    internal fun validateOCSPResponse(responseBytes: ByteArray, subjectCertificate: X509Certificate, issuerCertificate: X509Certificate?) { // Changed to internal for testing
        val ocspResp = OCSPResp(responseBytes)
        if (ocspResp.status != OCSPRespBuilder.SUCCESSFUL) {
            throw CertificateException("OCSP response unsuccessful. Status: ${ocspResp.status}")
        }

        val basicOCSPResp = ocspResp.responseObject as? BasicOCSPResp
            ?: throw CertificateException("OCSP response object is not a BasicOCSPResp or is null.")

        // Verify the signature and trustworthiness of the OCSP response itself
        if (!verifyOCSPResponseSignature(basicOCSPResp, subjectCertificate, issuerCertificate)) {
            throw CertificateException("OCSP response signature validation failed.")
        }

        val responses = basicOCSPResp.responses
        if (responses.isEmpty()) {
            throw CertificateException("No individual responses in BasicOCSPResp.")
        }

        val singleResp = responses[0] // Assuming the first response is for our certificate

        // Verify that the response is for the correct certificate
        val expectedCertId = generateCertificateID(subjectCertificate, issuerCertificate)
        if (singleResp.certID != expectedCertId) {
            // Log details of expected vs actual
            logger.warn("OCSP Response CertID mismatch. Expected: NameHash=${expectedCertId.getIssuerNameHash()?.let { String(it) }}, KeyHash=${expectedCertId.getIssuerKeyHash()?.let { String(it) }}, Serial=${expectedCertId.getSerialNumber()}")
            logger.warn("Actual CertID: NameHash=${singleResp.certID.getIssuerNameHash()?.let { String(it) }}, KeyHash=${singleResp.certID.getIssuerKeyHash()?.let { String(it) }}, Serial=${singleResp.certID.getSerialNumber()}")
            throw CertificateException("OCSP response is for a different certificate. Serial numbers: Expected=${expectedCertId.serialNumber}, Actual=${singleResp.certID.serialNumber}")
        }
        
        // Check the status of the certificate
        val certStatus = singleResp.certStatus
        when {
            certStatus == CertificateStatus.GOOD -> logger.info("OCSP status is GOOD for certificate: {}", subjectCertificate.subjectX500Principal)
            certStatus is RevokedStatus -> {
                val revokedStatus = certStatus as RevokedStatus
                val revocationTime = revokedStatus.revocationTime
                val reason = revokedStatus.revocationReason // This is an int, map to string if needed
                throw CertificateException("Certificate is REVOKED. Time: $revocationTime, Reason: $reason. Subject: ${subjectCertificate.subjectX500Principal}")
            }
            certStatus is UnknownStatus -> throw CertificateException("OCSP status is UNKNOWN for certificate: ${subjectCertificate.subjectX500Principal}")
            else -> logger.info("OCSP status is GOOD (null status) for certificate: {}", subjectCertificate.subjectX500Principal) // Treat null as GOOD
        }

        // Optionally, check 'thisUpdate', 'nextUpdate' times from singleResp
        // singleResp.thisUpdate, singleResp.nextUpdate
    }
    
    internal fun generateCertificateID(subjectCertificate: X509Certificate, issuerCertificate: X509Certificate?): CertificateID { // Changed to internal for testing
         if (issuerCertificate == null) {
            throw CertificateException("Issuer certificate is required for generating CertificateID for OCSP validation for ${subjectCertificate.subjectX500Principal}")
        }
        try {
            val issuerCertHolder = X509CertificateHolder(issuerCertificate.encoded)
            val subjectCertHolder = X509CertificateHolder(subjectCertificate.encoded)
            val digestCalculator = JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build()
                .get(CertificateID.HASH_SHA1)
            return CertificateID(digestCalculator, issuerCertHolder, subjectCertHolder.serialNumber)
        } catch (e: Exception) {
            throw CertificateException("Failed to generate CertificateID: ${e.message}", e)
        }
    }


    internal fun checkCRL(cert: X509Certificate) { // Renamed parameter to avoid conflict, changed to internal for testing
        val crlUrls = getCRLUrls(cert)
        if (crlUrls.isEmpty()) {
            logger.debug("No CRL URLs found in certificate: {}", cert.subjectX500Principal)
            return
        }

        for (crlUrl in crlUrls) {
            logger.debug("Checking CRL at: {} for certificate: {}", crlUrl, cert.subjectX500Principal)
            val request = HttpRequest.newBuilder()
                .uri(URI.create(crlUrl))
                .GET()
                .build()

            try {
                val response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray())
                if (response.statusCode() != 200) {
                    logger.warn("CRL request failed with status: {}", response.statusCode())
                    continue
                }

                val crl = parseCRL(response.body())
                if (crl.isRevoked(cert)) {
                    throw CertificateException("Certificate is revoked according to CRL")
                }
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("CRL check interrupted", e)
            }
        }
    }

    private fun getOCSPUrl(cert: X509Certificate): String? {
        try {
            val extensionValue = cert.getExtensionValue(Extension.authorityInfoAccess.id)
            if (extensionValue == null) {
                logger.debug("No Authority Information Access extension found in certificate: {}", cert.subjectX500Principal)
                return null
            }

            val derOctetString = ASN1InputStream(ByteArrayInputStream(extensionValue)).readObject() as? DEROctetString
                ?: throw IOException("Could not convert extension value to DEROctetString")
            
            val asn1Primitive = ASN1InputStream(ByteArrayInputStream(derOctetString.octets)).readObject()
            val aia = AuthorityInformationAccess.getInstance(asn1Primitive)

            for (accessDescription in aia.accessDescriptions) {
                if (accessDescription.accessMethod == X509ObjectIdentifiers.id_ad_ocsp) {
                    val generalName = accessDescription.accessLocation
                    if (generalName.tagNo == GeneralName.uniformResourceIdentifier) {
                        val uri = DERIA5String.getInstance(generalName.name).string
                        logger.debug("Found OCSP URL: {} in certificate: {}", uri, cert.subjectX500Principal)
                        return uri
                    }
                }
            }
            logger.debug("No OCSP URL found in AIA extension for certificate: {}", cert.subjectX500Principal)
        } catch (e: Exception) {
            logger.warn("Failed to extract OCSP URL from certificate {}: {}", cert.subjectX500Principal, e.message, e)
        }
        return null
    }

    private fun getCRLUrls(cert: X509Certificate): List<String> {
        val urls = mutableListOf<String>()
        try {
            val extensionValue = cert.getExtensionValue(Extension.cRLDistributionPoints.id)
            if (extensionValue == null) {
                logger.debug("No CRL Distribution Points extension found in certificate: {}", cert.subjectX500Principal)
                return urls
            }
            
            val derOctetString = ASN1InputStream(ByteArrayInputStream(extensionValue)).readObject() as? DEROctetString
                ?: throw IOException("Could not convert extension value to DEROctetString")

            val asn1Primitive = ASN1InputStream(ByteArrayInputStream(derOctetString.octets)).readObject()
            val crlDistPoint = CRLDistPoint.getInstance(asn1Primitive)

            for (distributionPoint in crlDistPoint.distributionPoints) {
                val dpName = distributionPoint.distributionPoint
                if (dpName != null && dpName.type == DistributionPointName.FULL_NAME) {
                    val generalNames = GeneralNames.getInstance(dpName.name)
                    for (generalName in generalNames.names) {
                        if (generalName.tagNo == GeneralName.uniformResourceIdentifier) {
                            val uri = DERIA5String.getInstance(generalName.name).string
                            urls.add(uri)
                            logger.debug("Found CRL URL: {} in certificate: {}", uri, cert.subjectX500Principal)
                        }
                    }
                }
            }
            if (urls.isEmpty()) {
                logger.debug("No CRL URLs found in CRL Distribution Points extension for certificate: {}", cert.subjectX500Principal)
            }
        } catch (e: Exception) {
            logger.warn("Failed to extract CRL URLs from certificate {}: {}", cert.subjectX500Principal, e.message, e)
        }
        return urls
    }

    internal fun parseCRL(crlData: ByteArray): X509CRL { // Changed to internal for testing
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCRL(ByteArrayInputStream(crlData)) as X509CRL
        } catch (e: CertificateException) {
            throw CRLException("Failed to parse CRL: ${e.message}", e)
        }
    }

    private fun verifyOCSPResponseSignature(
        basicOCSPResp: BasicOCSPResp,
        subjectCertificate: X509Certificate, // Certificate whose status is being checked
        issuerCertificate: X509Certificate?  // Issuer of subjectCertificate
    ): Boolean {
        val respCerts = basicOCSPResp.certs
        var signerCert: X509Certificate? = null

        if (respCerts == null || respCerts.isEmpty()) {
            logger.warn("OCSP response does not contain any certificates. Cannot verify signature for subject: {}.", subjectCertificate.subjectX500Principal)
            // Depending on policy, this could be a failure. For now, log and try to proceed if a local resolver is available,
            // but current logic relies on embedded certs or cert issued by subject's issuer.
            // If there is a pre-configured OCSP responder cert, that could be used here.
            // For now, if failOnError is strict, this should be false.
            return false // Cannot verify signature without responder's certificate.
        }

        val responderId = basicOCSPResp.responderId
        val extensionUtils = JcaX509ExtensionUtils()

        for (certHolder in respCerts) {
            val currentCert = try {
                x509CertificateConverter.getCertificate(certHolder)
            } catch (e: CertificateException) {
                logger.warn("Error converting X509CertificateHolder to X509Certificate: {}", e.message)
                continue
            }

            if (responderId.matches(certHolder)) { // BouncyCastle's ResponderID.matches checks both by name and by key hash
                signerCert = currentCert
                logger.debug("Potential OCSP signer certificate found: Subject='{}'", signerCert.subjectX500Principal)
                break
            }
        }

        if (signerCert == null) {
            logger.warn("No matching OCSP signer certificate found in the response for ResponderID: {}. Subject: {}", responderId.toASN1Primitive(), subjectCertificate.subjectX500Principal)
            return false
        }

        // 2. Signature Verification
        try {
            val sigAlgName = sigAlgNameFinder.getAlgorithmName(basicOCSPResp.signatureAlgorithmID)
            val signature = Signature.getInstance(sigAlgName, BouncyCastleProvider.PROVIDER_NAME)
            signature.initVerify(signerCert.publicKey)
            signature.update(basicOCSPResp.tbsResponseData)

            if (!signature.verify(basicOCSPResp.signature)) {
                logger.warn("OCSP response signature verification failed for subject: {}. Signer: {}", subjectCertificate.subjectX500Principal, signerCert.subjectX500Principal)
                return false
            }
            logger.info("OCSP response signature verified successfully for subject: {}. Signer: {}", subjectCertificate.subjectX500Principal, signerCert.subjectX500Principal)
        } catch (e: Exception) {
            logger.error("Error during OCSP signature verification for subject: {}: {}", subjectCertificate.subjectX500Principal, e.message, e)
            return false
        }

        // 3. Check OCSP Signing Extension
        try {
            val extendedKeyUsage = signerCert.extendedKeyUsage
            if (extendedKeyUsage == null || !extendedKeyUsage.contains(KeyPurposeId.id_kp_OCSPSigning.id)) {
                logger.warn("OCSP signer certificate '{}' for subject '{}' does not have id_kp_OCSPSigning extended key usage.", signerCert.subjectX500Principal, subjectCertificate.subjectX500Principal)
                // Depending on policy, this might not be a fatal error. For now, just log.
            }
        } catch (e: java.security.cert.CertificateParsingException) {
            logger.warn("Could not parse extendedKeyUsage for OCSP signer cert {}: {}", signerCert.subjectX500Principal, e.message)
        }

        // 4. Trustworthiness of Responder (Simplified)
        if (issuerCertificate != null) {
            if (signerCert.issuerX500Principal == issuerCertificate.subjectX500Principal) {
                try {
                    signerCert.verify(issuerCertificate.publicKey, BouncyCastleProvider.PROVIDER_NAME)
                    logger.info("OCSP signer certificate '{}' is directly issued by the subject's issuer '{}'.", signerCert.subjectX500Principal, issuerCertificate.subjectX500Principal)
                } catch (e: Exception) {
                    logger.warn("OCSP signer certificate '{}' appears to be issued by subject's issuer '{}', but signature verification failed: {}. Full chain validation might be needed.",
                        signerCert.subjectX500Principal, issuerCertificate.subjectX500Principal, e.message)
                    // This is a more serious issue if it claims to be issued by issuer but fails verification.
                    return false // Or handle as per strict policy.
                }
            } else {
                logger.warn("OCSP signer certificate '{}' for subject '{}' is not directly issued by the subject's issuer '{}'. Full trust chain validation for the OCSP responder's certificate is recommended for production environments.",
                    signerCert.subjectX500Principal, subjectCertificate.subjectX500Principal, issuerCertificate.subjectX500Principal)
                // This is a warning; the signature was valid, but the responder's chain of trust is not fully checked here.
            }
        } else {
             logger.warn("Issuer certificate for subject '{}' was not provided. Cannot perform simplified trust check for OCSP signer certificate '{}'.",
                subjectCertificate.subjectX500Principal, signerCert.subjectX500Principal)
        }
        
        return true // If all checks passed or resulted in warnings (not hard failures)
    }
}