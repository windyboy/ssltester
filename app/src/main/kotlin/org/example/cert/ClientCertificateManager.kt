package org.example.cert

import org.example.config.SSLTestConfig
import org.slf4j.LoggerFactory
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import java.io.FileReader
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import java.nio.file.Files
import java.security.cert.CertificateException
import java.io.StringReader
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import java.io.InputStreamReader
import java.io.ByteArrayInputStream

/**
 * Manages client certificates for SSL/TLS connections.
 * Handles loading and configuring client certificates and private keys.
 */
class ClientCertificateManager(private val config: SSLTestConfig) {
    private val logger = LoggerFactory.getLogger(ClientCertificateManager::class.java)

    init {
        // Add BouncyCastle as a security provider if not already present
        Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) ?: Security.addProvider(BouncyCastleProvider())
    }

    /**
     * Creates an SSLSocketFactory configured with the client certificate if specified.
     * @return SSLSocketFactory configured with client certificate, or null if no client certificate is specified
     */
    fun createSSLSocketFactory(): SSLSocketFactory? {
        if (config.clientCertFile == null || config.clientKeyFile == null) {
            return null
        }

        try {
            // Load client certificate
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert = certFactory.generateCertificate(FileInputStream(config.clientCertFile)) as X509Certificate

            // Create a temporary keystore
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, null)
            keyStore.setKeyEntry(
                "client",
                loadPrivateKey(),
                config.clientKeyPassword?.toCharArray() ?: "".toCharArray(),
                arrayOf(cert)
            )

            // Initialize KeyManagerFactory
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, config.clientKeyPassword?.toCharArray() ?: "".toCharArray())

            // Create SSLContext
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(kmf.keyManagers, null, null)

            return sslContext.socketFactory
        } catch (e: Exception) {
            logger.error("Failed to create SSLSocketFactory with client certificate", e)
            return null
        }
    }

    internal fun loadPrivateKey(): PrivateKey {
        if (config.clientKeyFile == null) {
            throw IllegalArgumentException("Client key file not specified")
        }

        try {
            val keyFile = config.clientKeyFile!!
            val keyBytes = Files.readAllBytes(keyFile.toPath())
            val pemObject = PEMParser(InputStreamReader(ByteArrayInputStream(keyBytes))).readObject()

            return when (pemObject) {
                is PEMKeyPair -> {
                    val keyPair = pemObject
                    val keyFactory = KeyFactory.getInstance(keyPair.privateKeyInfo.privateKeyAlgorithm.algorithm.id)
                    keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyPair.privateKeyInfo.encoded))
                }
                is PEMEncryptedKeyPair -> {
                    val password = config.clientKeyPassword?.toCharArray() 
                        ?: throw IllegalArgumentException("Password required for encrypted key")
                    val decryptor = JcePEMDecryptorProviderBuilder().build(password)
                    val keyPair = pemObject.decryptKeyPair(decryptor)
                    val keyFactory = KeyFactory.getInstance(keyPair.privateKeyInfo.privateKeyAlgorithm.algorithm.id)
                    keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyPair.privateKeyInfo.encoded))
                }
                is PKCS8EncryptedPrivateKeyInfo -> {
                    val password = config.clientKeyPassword?.toCharArray() 
                        ?: throw IllegalArgumentException("Password required for encrypted key")
                    val decryptor = JceOpenSSLPKCS8DecryptorProviderBuilder().build(password)
                    val keyInfo = pemObject.decryptPrivateKeyInfo(decryptor)
                    val keyFactory = KeyFactory.getInstance(keyInfo.privateKeyAlgorithm.algorithm.id)
                    keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyInfo.encoded))
                }
                is PrivateKeyInfo -> {
                    val keyFactory = KeyFactory.getInstance(pemObject.privateKeyAlgorithm.algorithm.id)
                    keyFactory.generatePrivate(PKCS8EncodedKeySpec(pemObject.encoded))
                }
                else -> throw IllegalArgumentException("Unsupported PEM object type: ${pemObject.javaClass.name}")
            }
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to load private key: ${e.message}", e)
        }
    }

    private fun loadClientCertificate(certFile: File): X509Certificate {
        return try {
            val cf = CertificateFactory.getInstance("X.509")
            certFile.inputStream().use { stream ->
                cf.generateCertificate(stream) as X509Certificate
            }
        } catch (e: Exception) {
            throw CertificateException("Failed to load client certificate: ${e.message}", e)
        }
    }

    private fun loadClientKey(): PrivateKey? {
        try {
            config.clientKeyFile?.let { keyFile ->
                val keyFactory = KeyFactory.getInstance("RSA")
                val keySpec = PKCS8EncodedKeySpec(keyFile.readBytes())
                return keyFactory.generatePrivate(keySpec)
            }
        } catch (e: Exception) {
            logger.error("Failed to load client key: ${e.message}")
        }
        return null
    }
}