package org.example.cert

import org.slf4j.LoggerFactory
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertPath
import java.security.cert.CertPathValidator
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.example.config.SSLTestConfig
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.net.InetAddress
import org.bouncycastle.asn1.DEROctetString

/**
 * A class for validating X.509 certificates and certificate chains.
 * Provides functionality for certificate chain validation, hostname verification,
 * and certificate information extraction.
 */
open class CertificateValidator(
    private val config: SSLTestConfig
) : X509TrustManager {
    private val logger = LoggerFactory.getLogger(CertificateValidator::class.java)
    private val trustManagerFactory: TrustManagerFactory
    private val delegateTrustManager: X509TrustManager

    init {
        trustManagerFactory = initializeTrustManagerFactory()
        delegateTrustManager = findX509TrustManager(trustManagerFactory)
    }

    /**
     * Validates a certificate chain against the configured trust store.
     *
     * @param certs The array of certificates to validate
     * @param hostname The hostname to verify against the certificate
     * @return The validated X509Certificate array
     * @throws CertificateException if the certificate chain is invalid
     */
    @Throws(CertificateException::class)
    fun validateCertificateChain(certs: Array<Certificate>?, hostname: String): Array<X509Certificate> {
        if (certs.isNullOrEmpty()) {
            throw CertificateException("Certificate chain is empty")
        }

        val x509Certs = certs.map { it as X509Certificate }.toTypedArray()

        try {
            // Check validity dates for all certificates
            for (cert in x509Certs) {
                try {
                    cert.checkValidity()
                } catch (e: CertificateExpiredException) {
                    throw CertificateException("Certificate has expired: ${cert.subjectX500Principal}", e)
                } catch (e: CertificateNotYetValidException) {
                    throw CertificateException("Certificate is not yet valid: ${cert.subjectX500Principal}", e)
                }
            }

            // Special handling for self-signed certificates
            if (x509Certs.size == 1 && isSelfSigned(x509Certs[0])) {
                validateSelfSignedCertificate(x509Certs[0], hostname)
                return x509Certs
            }

            // Validate certificate chain using PKIX path validation
            validateCertificatePath(x509Certs)

            // Hostname verification
            if (!verifyHostname(x509Certs[0], hostname)) {
                throw CertificateException("Hostname verification failed: '$hostname' does not match certificate's Subject Alternative Names or Common Name")
            }

            logger.info("→ Certificate chain validation successful for: {}", hostname)
            return x509Certs
        } catch (e: CertificateException) {
            logger.error("Certificate validation failed: {}", e.message)
            throw e
        } catch (e: Exception) {
            logger.error("Unexpected error during certificate validation", e)
            throw CertificateException("Certificate validation failed: ${e.message}", e)
        }
    }

    /**
     * Validates a self-signed certificate.
     */
    @Throws(CertificateException::class)
    private fun validateSelfSignedCertificate(cert: X509Certificate, hostname: String) {
        logger.debug("Validating self-signed certificate: {}", cert.subjectX500Principal)

        // Verify signature
        try {
            cert.verify(cert.publicKey)
        } catch (e: Exception) {
            throw CertificateException("Self-signed certificate signature is invalid", e)
        }

        // Check if it's in our trust store
        try {
            delegateTrustManager.checkServerTrusted(arrayOf(cert), cert.publicKey.algorithm)
            logger.info("→ Self-signed certificate trusted by trust manager")
        } catch (e: CertificateException) {
            throw CertificateException("Self-signed certificate not trusted by trust manager", e)
        }

        // Hostname verification
        if (!verifyHostname(cert, hostname)) {
            throw CertificateException("Hostname verification failed: '$hostname' does not match certificate's Subject Alternative Names or Common Name")
        }
    }

    /**
     * Validates a certificate path using the PKIX algorithm.
     */
    @Throws(CertificateException::class)
    private fun validateCertificatePath(certificates: Array<X509Certificate>) {
        try {
            // First verify using the delegate trust manager
            val authType = certificates[0].publicKey.algorithm
            delegateTrustManager.checkServerTrusted(certificates, authType)

            // Additional PKIX validation
            val cf = CertificateFactory.getInstance("X.509")
            val certPath = cf.generateCertPath(certificates.toList())

            // Get the trust anchors from the trust manager
            val trustAnchors = delegateTrustManager.acceptedIssuers.mapTo(HashSet()) {
                java.security.cert.TrustAnchor(it, null)
            }

            if (trustAnchors.isEmpty()) {
                logger.warn("No trust anchors available for PKIX validation")
                return // Skip PKIX validation if no trust anchors
            }

            val params = PKIXParameters(trustAnchors)
            params.isRevocationEnabled = false // Disable revocation checking for performance

            val validator = CertPathValidator.getInstance("PKIX")
            validator.validate(certPath, params)

            logger.debug("PKIX path validation successful")
        } catch (e: Exception) {
            logger.error("PKIX validation failed", e)
            throw CertificateException("Certificate path validation failed: ${e.message}", e)
        }
    }

    /**
     * Checks if a certificate is self-signed.
     */
    private fun isSelfSigned(cert: X509Certificate): Boolean {
        return cert.subjectX500Principal == cert.issuerX500Principal
    }

    /**
     * Initializes the TrustManagerFactory with either a custom or system keystore.
     */
    @Throws(CertificateException::class)
    protected open fun initializeTrustManagerFactory(): TrustManagerFactory {
        try {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())

            if (config.keystoreFile != null) {
                // Use custom keystore
                val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                FileInputStream(config.keystoreFile).use { fis ->
                    keystore.load(fis, config.keystorePassword?.toCharArray())
                }
                trustManagerFactory.init(keystore)
                logger.info("Initialized trust manager with custom keystore: {}", config.keystoreFile)
            } else {
                // Use system default trust store
                trustManagerFactory.init(null as KeyStore?)
                logger.info("Initialized trust manager with system default trust store")
            }

            return trustManagerFactory
        } catch (e: Exception) {
            throw CertificateException("Failed to initialize TrustManagerFactory: ${e.message}", e)
        }
    }

    /**
     * Finds and returns an X509TrustManager from the provided TrustManagerFactory.
     */
    @Throws(CertificateException::class)
    protected open fun findX509TrustManager(tmf: TrustManagerFactory): X509TrustManager {
        return tmf.trustManagers.find { it is X509TrustManager } as? X509TrustManager
            ?: throw CertificateException("No X509TrustManager found in TrustManagerFactory")
    }

    /**
     * Verifies if the hostname matches the certificate's Subject Alternative Names or Common Name.
     *
     * @param cert The certificate to verify
     * @param hostname The hostname to check against
     * @return true if the hostname matches, false otherwise
     */
    fun verifyHostname(cert: X509Certificate, hostname: String): Boolean {
        if (hostname.isEmpty()) {
            return false
        }

        // First check Subject Alternative Names (preferred according to RFC 6125)
        val subjectAlternativeNames = cert.getSubjectAlternativeNames()
        if (subjectAlternativeNames != null) {
            for (san in subjectAlternativeNames) {
                val type = san[0] as Int
                if (type == 2) { // DNS name
                    val dnsName = san[1] as String
                    if (matchHostname(hostname, dnsName)) {
                        logger.debug("Hostname '{}' matches SAN: {}", hostname, dnsName)
                        return true
                    }
                } else if (type == 7) { // IP address
                    val ipAddress = san[1] as String
                    if (hostname == ipAddress) {
                        logger.debug("Hostname '{}' matches IP SAN: {}", hostname, ipAddress)
                        return true
                    }
                }
            }
        }

        // Fall back to Common Name (deprecated but still used)
        val subjectDN = cert.subjectX500Principal.name
        val cnPattern = "CN=([^,]+)".toRegex()
        val match = cnPattern.find(subjectDN)
        if (match != null) {
            val cn = match.groupValues[1]
            val result = matchHostname(hostname, cn)
            if (result) {
                logger.debug("Hostname '{}' matches CN: {}", hostname, cn)
            }
            return result
        }

        logger.debug("Hostname '{}' does not match any SAN or CN in certificate", hostname)
        return false
    }

    /**
     * Matches a hostname against a pattern, handling wildcards according to RFC 6125.
     */
    private fun matchHostname(hostname: String, pattern: String): Boolean {
        // Convert to lowercase for case-insensitive comparison
        val hostnameLower = hostname.lowercase(Locale.ROOT)
        val patternLower = pattern.lowercase(Locale.ROOT)

        // Handle wildcard certificates
        if (patternLower.startsWith("*.")) {
            // Wildcard should match exactly one label
            val patternDomain = patternLower.substring(2)
            val hostnameParts = hostnameLower.split('.')

            // Wildcard doesn't match if hostname has fewer than 2 parts
            if (hostnameParts.size < 2) return false

            // Remove the first label and join the rest
            val hostnameDomain = hostnameParts.drop(1).joinToString(".")
            return hostnameDomain == patternDomain
        }

        return hostnameLower == patternLower
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Not used in this implementation
        throw CertificateException("Client certificate validation not supported")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain == null || chain.isEmpty()) {
            throw CertificateException("Certificate chain is null or empty")
        }

        try {
            // First check validity dates for each certificate
            for (cert in chain) {
                cert.checkValidity()
            }

            // Use the delegate trust manager for the actual validation
            delegateTrustManager.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            throw e
        } catch (e: Exception) {
            throw CertificateException("Certificate validation failed: ${e.message}", e)
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        // Return the accepted issuers from the delegate trust manager
        return delegateTrustManager.acceptedIssuers
    }
}