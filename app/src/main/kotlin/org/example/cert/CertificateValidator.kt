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

/**
 * A class for validating X.509 certificates and certificate chains.
 * Provides functionality for certificate chain validation, hostname verification,
 * and certificate information extraction.
 */
class CertificateValidator(
    private val config: SSLTestConfig
) : X509TrustManager {
    private val logger = LoggerFactory.getLogger(CertificateValidator::class.java)
    private val revocationChecker: CertificateRevocationChecker

    init {
        revocationChecker = CertificateRevocationChecker(
            checkOCSP = config.checkOCSP,
            checkCRL = config.checkCRL,
            failOnError = true // Defaulting to true, can be made configurable if needed
        )
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
            throw CertificateException("No certificates provided")
        }

        val x509Certs = certs.map { it as X509Certificate }.toTypedArray()
        
        // Check cache
        val certKey = getCertificateKey(x509Certs[0])
        CERTIFICATE_CACHE[certKey]?.let { cachedResult ->
            if (cachedResult) {
                logger.info("→ Certificate chain trusted (from cache)")
                // Also check hostname, this was already done by SSLTest before calling this method,
                // but keeping it here as a safeguard or if called from elsewhere.
                if (!verifyHostname(x509Certs[0], hostname)) {
                    throw CertificateException("Hostname does not match certificate (cached check)")
                }
                return x509Certs
            } else {
                // If it was in cache as not trusted, re-throw.
                // This specific path might need review if a negative cache entry should be re-validated.
                throw CertificateException("Certificate chain not trusted (from cache)")
            }
        }

        val tmf = initializeTrustManagerFactory()
        val tm = findX509TrustManager(tmf)
        val authType = x509Certs[0].publicKey.algorithm // Determine authType from leaf certificate

        try {
            // Perform standard trust validation using the determined authType
            tm.checkServerTrusted(x509Certs, authType)
            logger.info("→ Certificate chain trusted by system/custom trust manager for authType: {}", authType)
            
            // Perform hostname verification again (as tm.checkServerTrusted doesn't do it)
            // SSLTest already does this before calling validateCertificateChain, but this is a double check.
            if (!verifyHostname(x509Certs[0], hostname)) {
                CERTIFICATE_CACHE[certKey] = false // Cache as not trusted due to hostname mismatch
                throw CertificateException("Hostname verification failed: '$hostname' does not match certificate's Subject Alternative Names or Common Name.")
            }
            logger.info("→ Hostname verification successful for: {}", hostname)

            // Check revocation status for each certificate in the chain
            // This should ideally be done after basic chain validation and hostname verification.
            x509Certs.forEachIndexed { index, cert ->
                val issuer = if (index + 1 < x509Certs.size) x509Certs[index + 1] else null
                // Only perform revocation check if OCSP or CRL is enabled in config
                if (config.checkOCSP || config.checkCRL) {
                    logger.debug("Performing revocation check for: {} with issuer: {}", cert.subjectX500Principal, issuer?.subjectX500Principal ?: "N/A (self-signed or root)")
                    revocationChecker.checkRevocation(cert, issuer)
                } else {
                    logger.debug("Skipping revocation check as both OCSP and CRL are disabled.")
                }
            }
            if (config.checkOCSP || config.checkCRL) {
                logger.info("→ Revocation checks passed (if enabled and applicable for each certificate)")
            }


            CERTIFICATE_CACHE[certKey] = true // Cache as trusted
            return x509Certs
        } catch (e: CertificateException) {
            CERTIFICATE_CACHE[certKey] = false
            throw e
        }
    }

    private fun getCertificateKey(cert: X509Certificate): String {
        return "${cert.serialNumber.toString(16)}_${cert.issuerX500Principal.name}"
    }

    @Throws(CertificateException::class)
    private fun initializeTrustManagerFactory(): TrustManagerFactory {
        try {
            val tmf = TrustManagerFactory.getInstance("PKIX")
            val pkixParams: PKIXBuilderParameters

            if (config.keystoreFile != null) {
                logger.debug("Using custom keystore: {}", config.keystoreFile!!.absolutePath)
                val ks = KeyStore.getInstance(KeyStore.getDefaultType())
                ks.load(
                    config.keystoreFile!!.toURI().toURL().openStream(),
                    config.keystorePassword?.toCharArray()
                )
                tmf.init(ks)
                pkixParams = PKIXBuilderParameters(ks, X509CertSelector())
            } else {
                logger.debug("Using system default truststore.")
                val systemTrustStore = getSystemTrustStore()
                pkixParams = PKIXBuilderParameters(systemTrustStore, X509CertSelector())
            }

            pkixParams.isRevocationEnabled = false
            logger.debug("Revocation checking disabled in PKIXBuilderParameters for tests.")

            tmf.init(CertPathTrustManagerParameters(pkixParams))
            return tmf
        } catch (e: Exception) {
            throw CertificateException("Failed to initialize PKIX trust manager: ${e.message}", e)
        }
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
        return tmf.trustManagers.firstOrNull { it is X509TrustManager } as? X509TrustManager
            ?: throw CertificateException("No X509TrustManager found")
    }

    /**
     * Extracts detailed information from a given X.509 certificate.
     * Information includes Subject DN, Issuer DN, version, serial number, validity period,
     * signature algorithm, public key algorithm, and Subject Alternative Names (SANs).
     *
     * @param cert The X509Certificate to extract information from
     * @return A Map where keys are descriptive strings and values are the corresponding certificate details
     * @throws Exception If there's an error parsing the certificate
     */
    @Throws(Exception::class)
    fun getCertificateInfo(cert: X509Certificate): Map<String, Any> {
        val certInfo = mutableMapOf<String, Any>()

        certInfo["subjectDN"] = cert.subjectX500Principal.name
        certInfo["issuerDN"] = cert.issuerX500Principal.name
        certInfo["version"] = cert.version
        certInfo["serialNumber"] = cert.serialNumber.toString(16).uppercase()
        certInfo["validFrom"] = DATE_FORMATTER.format(cert.notBefore.toInstant())
        certInfo["validUntil"] = DATE_FORMATTER.format(cert.notAfter.toInstant())
        certInfo["signatureAlgorithm"] = cert.sigAlgName
        certInfo["publicKeyAlgorithm"] = cert.publicKey.algorithm

        // Add Subject Alternative Names
        cert.subjectAlternativeNames?.let { sans ->
            val sanMap = mutableMapOf<String, String>()
            sans.forEach { san ->
                val type = san[0] as Int
                val value = san[1] as String
                val typeName = when (type) {
                    0 -> "Other"
                    1 -> "rfc822Name"
                    2 -> "DNS"
                    3 -> "x400Address"
                    4 -> "directoryName"
                    5 -> "ediPartyName"
                    6 -> "URI"
                    7 -> "IP"
                    8 -> "registeredID"
                    else -> "Unknown"
                }
                sanMap[typeName] = value
            }
            certInfo["subjectAlternativeNames"] = sanMap
        }

        return certInfo
    }

    /**
     * Verifies if the given hostname matches the certificate's Subject Alternative Names (SANs)
     * or Common Name (CN) in the Subject DN.
     *
     * @param cert The X509Certificate to verify against
     * @param hostname The hostname to verify
     * @return true if the hostname matches, false otherwise
     */
    fun verifyHostname(cert: X509Certificate, hostname: String): Boolean {
        try {
            if (hostname.isBlank()) {
                return false
            }

            logger.debug("Verifying hostname: {}", hostname)

            // Normalize hostname (handle internationalized domain names)
            val normalizedHostname = normalizeHostname(hostname)
            logger.debug("Normalized hostname: {}", normalizedHostname)

            // Check if hostname is an IP address
            val isIpAddress = isIpAddress(normalizedHostname)
            if (isIpAddress) {
                logger.debug("Hostname is detected as IP address. Calling verifyIpAddress.")
                return verifyIpAddress(cert, normalizedHostname)
            }

            // Check Subject Alternative Names (SANs)
            cert.subjectAlternativeNames?.let { sans ->
                logger.debug("Certificate SANs: {}", sans)
                for (san in sans) {
                    val type = san[0] as Int
                    val value = san[1] as String
                    // Only check DNS names (type 2) and IP addresses (type 7)
                    if ((type == 2 || type == 7) && matchesHostname(normalizedHostname, value)) {
                        return true
                    }
                }
            }

            // If no SANs match, check Common Name (CN) in Subject DN
            val subjectDN = cert.subjectX500Principal.name
            val cn = extractCommonName(subjectDN)
            return cn != null && matchesHostname(normalizedHostname, cn)
        } catch (e: Exception) {
            logger.error("Hostname verification failed: {}", e.message)
            return false
        }
    }

    private fun normalizeHostname(hostname: String): String {
        return try {
            IDN.toASCII(hostname)
        } catch (e: Exception) {
            logger.error("Failed to normalize hostname: {}", e.message)
            hostname
        }
    }

    private fun isIpAddress(hostname: String): Boolean {
        return try {
            InetAddress.getByName(hostname).hostAddress == hostname
        } catch (e: UnknownHostException) {
            false
        }
    }

    private fun verifyIpAddress(cert: X509Certificate, ipAddress: String): Boolean {
        try {
            val normalizedIp = InetAddress.getByName(ipAddress).hostAddress
            cert.subjectAlternativeNames?.let { sans ->
                logger.debug("Verifying IP address. Input: {}. Certificate SANs: {}", normalizedIp, sans)
                for (san in sans) {
                    val type = san[0] as Int
                    val value = san[1] as String
                    if (type == 7) { // IP address type
                        val certIp = InetAddress.getByName(value).hostAddress
                        logger.debug("Comparing cert SAN IP: {} to input: {}", certIp, normalizedIp)
                        if (certIp == normalizedIp) {
                            return true
                        }
                    }
                }
            }
            return false
        } catch (e: UnknownHostException) {
            logger.error("Invalid IP address format: {}", e.message)
            return false
        }
    }

    private fun matchesHostname(hostname: String, pattern: String): Boolean {
        if (hostname.equals(pattern, ignoreCase = true)) {
            return true
        }

        // Handle wildcard certificates according to RFC 6125
        if (pattern.startsWith("*.") && pattern.length > 2) {
            val domain = pattern.substring(2)
            if (hostname.lowercase().endsWith(domain.lowercase())) {
                val diff = hostname.length - domain.length
                if (diff > 0 && hostname[diff - 1] == '.') {
                    // Ensure there is exactly one subdomain (no additional dots)
                    val subdomain = hostname.substring(0, diff - 1)
                    return !subdomain.contains(".")
                }
            }
        }

        return false
    }

    private fun extractCommonName(subjectDN: String): String? {
        val cnPattern = "CN=([^,]+)".toRegex()
        return cnPattern.find(subjectDN)?.groupValues?.get(1)
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