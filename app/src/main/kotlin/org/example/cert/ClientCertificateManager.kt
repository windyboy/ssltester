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

    private fun loadPrivateKey(): PrivateKey {
        val keyFile = File(config.clientKeyFile ?: throw IllegalArgumentException("Client key file not specified"))
        if (!keyFile.exists()) {
            logger.error("Client key file not found: ${keyFile.absolutePath}")
            throw IllegalArgumentException("Client key file not found: ${keyFile.absolutePath}")
        }

        try {
            FileReader(keyFile).use { reader ->
                PEMParser(reader).use { pemParser ->
                    val pemObject = pemParser.readObject()

                    val privateKeyInfo: PrivateKeyInfo = when (pemObject) {
                        is PEMEncryptedKeyPair -> {
                            val password = config.clientKeyPassword ?: ""
                            val decryptorProvider = JcePEMDecryptorProviderBuilder().build(password.toCharArray())
                            val keyPair = pemObject.decryptKeyPair(decryptorProvider)
                            keyPair.privateKeyInfo
                        }
                        is PKCS8EncryptedPrivateKeyInfo -> { // PKCS#8 Encrypted
                            val password = config.clientKeyPassword ?: ""
                            val decryptorProvider = JcePEMDecryptorProviderBuilder().build(password.toCharArray())
                            val decryptedPrivateKeyInfo = pemObject.decryptPrivateKeyInfo(decryptorProvider)
                            decryptedPrivateKeyInfo
                        }
                        is PEMKeyPair -> { // PKCS#1 unencrypted
                            pemObject.privateKeyInfo
                        }
                        is PrivateKeyInfo -> { // PKCS#8 unencrypted
                            pemObject
                        }
                        else -> {
                            logger.error("Unsupported PEM object type: ${pemObject?.javaClass?.name}")
                            throw IllegalArgumentException("Unsupported PEM object type: ${pemObject?.javaClass?.name}")
                        }
                    }

                    val keySpec = PKCS8EncodedKeySpec(privateKeyInfo.encoded)
                    
                    // Try common key algorithms. PKCS8 should be self-describing, but sometimes KeyFactory needs a hint.
                    val keyFactory = try {
                        KeyFactory.getInstance(privateKeyInfo.privateKeyAlgorithm.algorithm.id)
                    } catch (e: Exception) {
                        // Fallback if algorithm ID is not directly usable or recognized
                        try {
                            KeyFactory.getInstance("RSA")
                        } catch (eRsa: Exception) {
                            try {
                                KeyFactory.getInstance("EC")
                            } catch (eEc: Exception) {
                               logger.error("Failed to get KeyFactory instance for RSA or EC", eEc)
                               throw eEc // rethrow if common types fail
                            }
                        }
                    }
                    return keyFactory.generatePrivate(keySpec)
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to load private key from ${keyFile.absolutePath}", e)
            throw RuntimeException("Failed to load private key from ${keyFile.absolutePath}", e)
        }
    }
}