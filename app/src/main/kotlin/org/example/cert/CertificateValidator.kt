package org.example.cert

import org.slf4j.LoggerFactory
import java.io.File
import java.io.InputStream
import java.net.IDN
import java.net.InetAddress
import java.net.UnknownHostException
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.PKIXBuilderParameters
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.CertPathTrustManagerParameters
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import org.example.config.SSLTestConfig
import org.bouncycastle.asn1.x509.GeneralName
import java.net.http.HttpClient
import java.time.Duration
import java.security.cert.CertificateFactory
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXCertPathChecker
import java.security.cert.PKIXParameters
import java.io.FileInputStream
import org.example.exception.SSLTestException

/**
 * A class for validating X.509 certificates and certificate chains.
 * Provides functionality for certificate chain validation, hostname verification,
 * and certificate information extraction.
 */
class CertificateValidator(
    private val config: SSLTestConfig
) : X509TrustManager {
    private val logger = LoggerFactory.getLogger(CertificateValidator::class.java)
    private val trustManagerFactory: TrustManagerFactory

    init {
        trustManagerFactory = initializeTrustManagerFactory()
    }

    companion object {
        private val DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z")
            .withZone(ZoneId.systemDefault())
        private val CERTIFICATE_CACHE = ConcurrentHashMap<String, Boolean>()
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
        
        // Check if chain has at least two certificates, unless it's a single self-signed certificate
        if (x509Certs.size < 2) {
            val cert = x509Certs[0]
            if (cert.subjectX500Principal != cert.issuerX500Principal) {
                throw CertificateException("Certificate chain must contain at least two certificates")
            }
            // For self-signed certificates, verify the signature
            try {
                cert.verify(cert.publicKey)
            } catch (e: Exception) {
                throw CertificateException("Self-signed certificate signature is invalid", e)
            }
            
            // For self-signed certificates, we need to check if it's in our trust store
            val tm = findX509TrustManager(trustManagerFactory)
            try {
                tm.checkServerTrusted(x509Certs, cert.publicKey.algorithm)
                logger.info("→ Self-signed certificate trusted by trust manager")
            } catch (e: CertificateException) {
                throw CertificateException("Self-signed certificate not trusted by trust manager", e)
            }
            
            // Hostname verification
            if (!verifyHostname(cert, hostname)) {
                throw CertificateException("Hostname verification failed: '$hostname' does not match certificate's Subject Alternative Names or Common Name.")
            }
            
            return x509Certs
        }

        // Validate certificate order (each certificate should be issued by the next one in the chain)
        for (i in 0 until x509Certs.size - 1) {
            val cert = x509Certs[i]
            val issuer = x509Certs[i + 1]
            if (cert.issuerX500Principal != issuer.subjectX500Principal) {
                throw CertificateException("Certificate chain is not in correct order")
            }
            try {
                cert.verify(issuer.publicKey)
            } catch (e: Exception) {
                throw CertificateException("Certificate signature is invalid", e)
            }
        }

        val tm = findX509TrustManager(trustManagerFactory)
        val authType = x509Certs[0].publicKey.algorithm

        try {
            // Perform standard trust validation
            tm.checkServerTrusted(x509Certs, authType)
            logger.info("→ Certificate chain trusted by trust manager for authType: {}", authType)
            
            // Hostname verification
            if (!verifyHostname(x509Certs[0], hostname)) {
                throw CertificateException("Hostname verification failed: '$hostname' does not match certificate's Subject Alternative Names or Common Name.")
            }
            logger.info("→ Hostname verification successful for: {}", hostname)

            return x509Certs
        } catch (e: CertificateException) {
            throw e
        }
    }

    private fun getCertificateKey(cert: X509Certificate): String {
        return "${cert.serialNumber.toString(16)}_${cert.issuerX500Principal.name}"
    }

    @Throws(CertificateException::class)
    private fun initializeTrustManagerFactory(): TrustManagerFactory {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        
        if (config.keystoreFile != null) {
            // Use custom keystore
            val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
            FileInputStream(config.keystoreFile).use { fis ->
                keystore.load(fis, config.keystorePassword?.toCharArray())
            }
            trustManagerFactory.init(keystore)
        } else {
            // Use system default trust store
            trustManagerFactory.init(null as KeyStore?)
        }
        
        return trustManagerFactory
    }

    /**
     * Loads the default system truststore (either 'jssecacerts' or 'cacerts' from the JRE's security directory).
     *
     * @return The loaded KeyStore object representing the system truststore
     * @throws CertificateException If the truststore file cannot be found, loaded, or if there's a KeyStore error
     */
    @Throws(CertificateException::class)
    private fun getSystemTrustStore(): KeyStore {
        try {
            val javaHome = System.getProperty("java.home")
            var trustStorePath = Paths.get(javaHome, "lib", "security", "jssecacerts")
            if (!Files.exists(trustStorePath)) {
                trustStorePath = Paths.get(javaHome, "lib", "security", "cacerts")
            }

            if (!Files.exists(trustStorePath)) {
                throw CertificateException("Could not find jssecacerts or cacerts in $javaHome")
            }
            logger.debug("Loading system truststore from: {}", trustStorePath)

            val trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
            Files.newInputStream(trustStorePath).use { fis ->
                // Default password for cacerts is "changeit"
                trustStore.load(fis, "changeit".toCharArray())
            }
            return trustStore
        } catch (e: KeyStoreException) {
            throw CertificateException("Failed to instantiate KeyStore for system truststore: ${e.message}", e)
        } catch (e: Exception) {
            throw CertificateException("Failed to load system truststore: ${e.message}", e)
        }
    }

    /**
     * Finds and returns an X509TrustManager from the provided TrustManagerFactory.
     *
     * @param tmf The TrustManagerFactory from which to extract the trust manager
     * @return The first X509TrustManager found
     * @throws CertificateException If no X509TrustManager is found in the factory
     */
    @Throws(CertificateException::class)
    private fun findX509TrustManager(tmf: TrustManagerFactory): X509TrustManager {
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
        val subjectAlternativeNames = cert.getSubjectAlternativeNames()
        if (subjectAlternativeNames != null) {
            for (san in subjectAlternativeNames) {
                val type = san[0] as Int
                if (type == 2) { // DNS
                    val dnsName = san[1] as String
                    if (matchHostname(hostname, dnsName)) {
                        return true
                    }
                }
            }
        }

        // Check CN in subject DN
        val subjectDN = cert.subjectX500Principal.name
        val cnPattern = "CN=([^,]+)".toRegex()
        val match = cnPattern.find(subjectDN)
        if (match != null) {
            val cn = match.groupValues[1]
            return matchHostname(hostname, cn)
        }

        return false
    }

    private fun matchHostname(hostname: String, pattern: String): Boolean {
        // Convert to lowercase for case-insensitive comparison
        val hostnameLower = hostname.lowercase()
        val patternLower = pattern.lowercase()

        // Handle wildcard certificates
        if (patternLower.startsWith("*.")) {
            val patternDomain = patternLower.substring(2)
            val hostnameDomain = hostnameLower.substringAfter('.')
            return hostnameDomain == patternDomain
        }

        return hostnameLower == patternLower
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Not used in this implementation
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (chain == null || chain.isEmpty()) {
            throw CertificateException("Certificate chain is null or empty")
        }

        // Check each certificate in the chain
        for (cert in chain) {
            try {
                cert.checkValidity()
            } catch (e: CertificateExpiredException) {
                throw CertificateException("Certificate has expired", e)
            } catch (e: CertificateNotYetValidException) {
                throw CertificateException("Certificate is not yet valid", e)
            }
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        return emptyArray()
    }
} 