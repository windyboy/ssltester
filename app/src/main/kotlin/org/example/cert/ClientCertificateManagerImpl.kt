package org.example.cert

import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import org.slf4j.LoggerFactory
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509KeyManager
import javax.net.ssl.X509TrustManager
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.KeyFactory
import java.util.Base64
import java.io.BufferedReader
import java.io.StringReader
import java.io.InputStream

interface FileProvider {
    fun inputStream(file: File): InputStream
    fun readText(file: File): String
    fun exists(file: File): Boolean
}

class DefaultFileProvider : FileProvider {
    override fun inputStream(file: File) = FileInputStream(file)
    override fun readText(file: File) = file.readText()
    override fun exists(file: File) = file.exists()
}

/**
 * Implementation of client certificate management with enhanced security features.
 */
class ClientCertificateManagerImpl(
    private val fileProvider: FileProvider = DefaultFileProvider()
) : ClientCertificateManager {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val SUPPORTED_KEY_TYPES = setOf("RSA", "EC")

    override fun createSSLSocketFactory(config: SSLTestConfig): SSLSocketFactory {
        try {
            val sslContext = createSSLContext(config)
            return sslContext.socketFactory
        } catch (e: Exception) {
            logger.error("Failed to create SSL socket factory: ${e.message}", e)
            throw SSLTestException("Failed to create SSL socket factory: ${e.message}")
        }
    }

    override fun createSSLContext(config: SSLTestConfig): SSLContext {
        try {
            val sslContext = SSLContext.getInstance("TLS")
            val keyManagers = createKeyManagers(config)
            val trustManagers = createTrustManagers(config)
            sslContext.init(keyManagers, trustManagers, null)
            return sslContext
        } catch (e: Exception) {
            logger.error("Failed to create SSL context: ${e.message}", e)
            throw SSLTestException("Failed to create SSL context: ${e.message}")
        }
    }

    override fun createTrustManagers(config: SSLTestConfig): Array<TrustManager> {
        try {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            if (config.trustStore != null) {
                val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
                fileProvider.inputStream(File(config.trustStore)).use { fis ->
                    keyStore.load(fis, config.trustStorePassword?.toCharArray())
                }
                trustManagerFactory.init(keyStore)
            } else {
                trustManagerFactory.init(null as KeyStore?)
            }
            return trustManagerFactory.trustManagers
        } catch (e: Exception) {
            logger.error("Failed to create trust managers: ${e.message}", e)
            throw SSLTestException("Failed to create trust managers: ${e.message}")
        }
    }

    override fun createTrustAllManager(): X509TrustManager {
        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
    }

    override fun createKeyManagers(config: SSLTestConfig): Array<X509KeyManager> {
        if (config.clientCertFile == null || config.clientKeyFile == null) {
            return emptyArray()
        }

        try {
            val certificate = loadClientCertificate(
                File(config.clientCertFile),
                File(config.clientKeyFile),
                config.clientKeyPassword
            )

            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, null)
            keyStore.setKeyEntry(
                "client",
                loadPrivateKey(File(config.clientKeyFile), config.clientKeyPassword),
                config.clientKeyPassword?.toCharArray() ?: "".toCharArray(),
                arrayOf(certificate)
            )

            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore, config.clientKeyPassword?.toCharArray() ?: "".toCharArray())

            return keyManagerFactory.keyManagers.filterIsInstance<X509KeyManager>().toTypedArray()
        } catch (e: Exception) {
            logger.error("Failed to create key managers: ${e.message}", e)
            throw SSLTestException("Failed to create key managers: ${e.message}")
        }
    }

    override fun loadClientCertificate(certFile: File, keyFile: File, password: String?): Certificate {
        try {
            val certFactory = CertificateFactory.getInstance("X.509")
            fileProvider.inputStream(certFile).use { fis ->
                return certFactory.generateCertificate(fis)
            }
        } catch (e: Exception) {
            logger.error("Failed to load client certificate: ${e.message}", e)
            throw SSLTestException("Failed to load client certificate: ${e.message}")
        }
    }

    override fun validateConfiguration(config: SSLTestConfig) {
        if (config.clientCertFile != null && !fileProvider.exists(File(config.clientCertFile))) {
            throw SSLTestException("Client certificate file does not exist: ${config.clientCertFile}")
        }
        if (config.clientKeyFile != null && !fileProvider.exists(File(config.clientKeyFile))) {
            throw SSLTestException("Client key file does not exist: ${config.clientKeyFile}")
        }
        if (config.trustStore != null && !fileProvider.exists(File(config.trustStore))) {
            throw SSLTestException("Trust store file does not exist: ${config.trustStore}")
        }
    }

    private fun loadPrivateKey(keyFile: File, password: String?): PrivateKey {
        try {
            val keyContent = fileProvider.readText(keyFile)
            val keyData = if (keyContent.contains("-----BEGIN PRIVATE KEY-----")) {
                // PKCS#8 format
                extractPEMContent(keyContent, "PRIVATE KEY")
            } else if (keyContent.contains("-----BEGIN RSA PRIVATE KEY-----")) {
                // PKCS#1 format
                extractPEMContent(keyContent, "RSA PRIVATE KEY")
            } else {
                throw SSLTestException("Unsupported private key format")
            }

            val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(keyData))
            val keyFactory = KeyFactory.getInstance("RSA") // Default to RSA, adjust if needed
            return keyFactory.generatePrivate(keySpec)
        } catch (e: Exception) {
            logger.error("Failed to load private key: ${e.message}", e)
            throw SSLTestException("Failed to load private key: ${e.message}")
        }
    }

    private fun extractPEMContent(content: String, type: String): String {
        val reader = BufferedReader(StringReader(content))
        val sb = StringBuilder()
        var inKey = false

        while (true) {
            val line = reader.readLine() ?: break
            if (line.contains("-----BEGIN $type-----")) {
                inKey = true
                continue
            }
            if (line.contains("-----END $type-----")) {
                break
            }
            if (inKey) {
                sb.append(line)
            }
        }

        return sb.toString()
    }
} 