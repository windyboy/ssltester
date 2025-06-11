package org.example.cert

import org.example.config.SSLTestConfig
import org.slf4j.LoggerFactory
// import java.io.File // No longer directly used if config.clientCertFile is a File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMEncryptedKeyPair
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import java.nio.file.Files
// import java.security.cert.CertificateException // No longer thrown by a public method directly
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
     * @return SSLSocketFactory configured with client certificate, or null if no client certificate is specified.
     * @throws RuntimeException if there's an error during SSLSocketFactory creation.
     */
    fun createSSLSocketFactory(): SSLSocketFactory? {
        val clientCertFile = config.clientCertFile ?: return null.also {
            logger.debug("Client certificate file not specified, cannot create SSLSocketFactory.")
        }
        val clientKeyFile = config.clientKeyFile ?: return null.also {
            logger.debug("Client key file not specified, cannot create SSLSocketFactory.")
        }

        try {
            // Load client certificate
            val certFactory = CertificateFactory.getInstance("X.509")
            val cert: X509Certificate = FileInputStream(clientCertFile).use { fis ->
                certFactory.generateCertificate(fis) as X509Certificate
            }

            // Load private key
            val privateKey = loadPrivateKey() // This will throw an exception if key loading fails

            // Create a temporary keystore
            val keyStore = KeyStore.getInstance("PKCS12")
            keyStore.load(null, null) // Initialize an empty keystore

            val keyPassword = config.clientKeyPassword?.toCharArray() ?: "".toCharArray()
            keyStore.setKeyEntry("client", privateKey, keyPassword, arrayOf(cert))

            // Initialize KeyManagerFactory
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(keyStore, keyPassword)

            // Create SSLContext
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(kmf.keyManagers, null, null)

            return sslContext.socketFactory
        } catch (e: Exception) {
            logger.error("Failed to create SSLSocketFactory with client certificate", e)
            // Consider wrapping in a more specific custom exception if needed
            throw RuntimeException("Failed to create SSLSocketFactory: ${e.message}", e)
        }
    }

    /**
     * Loads a private key from the configured client key file.
     * Supports various PEM-encoded key formats (plain, encrypted, PKCS8).
     *
     * @return The loaded [PrivateKey].
     * @throws IllegalArgumentException if the client key file is not specified, cannot be read,
     *                                  is in an unsupported format, or if a password is required
     *                                  for an encrypted key but not provided.
     */
    internal fun loadPrivateKey(): PrivateKey {
        val keyFile = config.clientKeyFile
            ?: throw IllegalArgumentException("Client key file not specified in configuration.")

        val keyBytes = try {
            Files.readAllBytes(keyFile.toPath())
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to read client key file: ${keyFile.path}", e)
        }

        PEMParser(InputStreamReader(ByteArrayInputStream(keyBytes))).use { pemParser ->
            val pemObject = pemParser.readObject()
                ?: throw IllegalArgumentException("Could not parse PEM object from key file: ${keyFile.path}")

            return when (pemObject) {
                is PEMKeyPair -> createPrivateKeyFromInfo(pemObject.privateKeyInfo, "PEMKeyPair")
                is PEMEncryptedKeyPair -> {
                    val password = config.clientKeyPassword?.toCharArray()
                        ?: throw IllegalArgumentException("Password required for encrypted PEMKeyPair from file: ${keyFile.path}")
                    val decryptor = JcePEMDecryptorProviderBuilder().build(password)
                    val keyPair = pemObject.decryptKeyPair(decryptor)
                    createPrivateKeyFromInfo(keyPair.privateKeyInfo, "decrypted PEMEncryptedKeyPair")
                }
                is PKCS8EncryptedPrivateKeyInfo -> {
                    val password = config.clientKeyPassword?.toCharArray()
                        ?: throw IllegalArgumentException("Password required for encrypted PKCS8PrivateKeyInfo from file: ${keyFile.path}")
                    val decryptor = JceOpenSSLPKCS8DecryptorProviderBuilder().build(password)
                    val privateKeyInfo = pemObject.decryptPrivateKeyInfo(decryptor)
                    createPrivateKeyFromInfo(privateKeyInfo, "decrypted PKCS8EncryptedPrivateKeyInfo")
                }
                is PrivateKeyInfo -> createPrivateKeyFromInfo(pemObject, "PrivateKeyInfo")
                else -> throw IllegalArgumentException(
                    "Unsupported PEM object type: ${pemObject.javaClass.name} in file: ${keyFile.path}"
                )
            }
        }
    }

    /**
     * Helper function to generate a [PrivateKey] from [PrivateKeyInfo].
     *
     * @param privateKeyInfo The [PrivateKeyInfo] object.
     * @param typeDescription A description of the key type for error messages.
     * @return The generated [PrivateKey].
     * @throws IllegalArgumentException if key generation fails.
     */
    private fun createPrivateKeyFromInfo(privateKeyInfo: PrivateKeyInfo, typeDescription: String): PrivateKey {
        return try {
            val keyFactory = KeyFactory.getInstance(privateKeyInfo.privateKeyAlgorithm.algorithm.id)
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyInfo.encoded))
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to generate private key from $typeDescription: ${e.message}", e)
        }
    }
}