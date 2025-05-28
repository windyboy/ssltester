package org.example.cert

import org.example.config.SSLTestConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.security.PrivateKey
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.EncryptionException
import org.bouncycastle.pkcs.PKCSException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import org.junit.jupiter.api.assertThrows

class ClientCertificateManagerTest {

    @TempDir
    lateinit var tempDir: Path

    private lateinit var keysDir: File

    @BeforeEach
    fun setUp() {
        Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) ?: Security.addProvider(BouncyCastleProvider())
        keysDir = Files.createDirectory(tempDir.resolve("keys")).toFile()
    }

    private fun createClientCertificateManager(keyFileName: String?, passwordOpt: String? = null): ClientCertificateManager {
        val config = SSLTestConfig()
        keyFileName?.let {
            config.clientKeyFile = File(keysDir, it).absolutePath
        }
        passwordOpt?.let {
            config.clientKeyPassword = it
        }
        return ClientCertificateManager(config)
    }

    private fun writeKeyFile(filename: String, content: String) {
        File(keysDir, filename).writeText(content)
    }

    private val rsaPkcs1Unencrypted = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIBOgIBAAJBALyM2dM/f9N8/N1YI7xSAChvM9t9j83gAR4nQyGUXxpNzP8gYn9S
        093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4CAwEAAQJBALyM2dM/f9N8/N1YI7xS
        AChvM9t9j83gAR4nQyGUXxpNzP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4G
        fQ4CAwEAAQJBALyM2dM/f9N8/N1YI7xSAChvM9t9j83gAR4nQyGUXxpNzP8gYn9S
        093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4CAwEAAQJBALyM2dM/f9N8/N1YI7xS
        AChvM9t9j83gAR4nQyGUXxpNzP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4G
        fQ4CAwEAAQJBALyM2dM/f9N8/N1YI7xSAChvM9t9j83gAR4nQyGUXxpNzP8gYn9S
        093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4=
        -----END RSA PRIVATE KEY-----
    """.trimIndent()

    private val rsaPkcs8Unencrypted = """
        -----BEGIN PRIVATE KEY-----
        MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8jNnTP3/TfPzd
        WCO8UgAobzPbff/N4AEeJ0MhlF8aTcz/IGJ/UtPd0dp9jZzUNn0OBn0OBn0OBn0O
        Bn0OBn0OAgMBAAECggEBALyM2dM/f9N8/N1YI7xSAChvM9t9/83gAR4nQyGUXxpN
        zP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4CAwEAAQKBgQC8jNnTP3/T
        fPzdWCO8UgAobzPbff/N4AEeJ0MhlF8aTcz/IGJ/UtPd0dp9jZzUNn0OBn0OBn0O
        Bn0OBn0OBn0OAgMBAAECgYEAryM2dM/f9N8/N1YI7xSAChvM9t9/83gAR4nQyGU
        XxpNzP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4CAwEAAQKBgQC8jNnTP
        3/TfPzdWCO8UgAobzPbff/N4AEeJ0MhlF8aTcz/IGJ/UtPd0dp9jZzUNn0OBn0OB
        n0OBn0OBn0OBn0OAgMBAAECgYEAryM2dM/f9N8/N1YI7xSAChvM9t9/83gAR4nQy
        GUXxpNzP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4CAwEAAQKBgQC8jNnTP
        3/TfPzdWCO8UgAobzPbff/N4AEeJ0MhlF8aTcz/IGJ/UtPd0dp9jZzUNn0OBn0OB
        n0OBn0OBn0OBn0OAgMBAAECgYEAryM2dM/f9N8/N1YI7xSAChvM9t9/83gAR4nQy
        GUXxpNzP8gYn9S093R2n2NnNQ2fQ4GfQ4GfQ4GfQ4GfQ4GfQ4=
        -----END PRIVATE KEY-----
    """.trimIndent()

    private val rsaPkcs1Encrypted = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: DES-EDE3-CBC,832F77E00F8673A9

        gJ3P62V3gQO2E99nN9gM/bN0kLKVzOJ3Z0ZNHMNzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O91JzV8O
        91JzV8O91JzV8O91JzV8O9Q=
        -----END RSA PRIVATE KEY-----
    """.trimIndent()

    private val rsaPkcs8Encrypted = """
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI7bpNXDsoF8oCAggA
        MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECLLSqYxR9NvkBIIEyORj2GsjG0hr
        /nJ5shv53M9P5LkXj7kBCr2VEM8fL7Mv9uJTEpT9wLSm7Ds2s2XvqwjTY7AHZ0ob
        7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5Q5k/pWVSFLGL4uscOAPf7MHRV
        zJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tBAQp2xTj6Y942s2s2XvqwjTY7A
        HZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5Q5k/pWVSFLGL4uscOAPf
        7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tBAQp2xTj6Y942s2s2Xvqw
        jTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5Q5k/pWVSFLGL4us
        cOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tBAQp2xTj6Y942s2s
        2XvqwjTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5Q5k/pWVSFL
        GL4uscOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tBAQp2xTj6Y9
        42s2s2XvqwjTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5Q5k/p
        WVSFLGL4uscOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tBAQp2x
        Tj6Y942s2s2XvqwjTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+tVIg5
        Q5k/pWVSFLGL4uscOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6gq9tB
        AQp2xTj6Y942s2s2XvqwjTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2YvH0+
        tVIg5Q5k/pWVSFLGL4uscOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RTAdJkG6
        gq9tBAQp2xTj6Y942s2s2XvqwjTY7AHZ0ob7cxt8kLqYd5zQ0Ywz/lMncN7zU8u2
        YvH0+tVIg5Q5k/pWVSFLGL4uscOAPf7MHRVzJ3jL30p2v4wW2b88S840yXmp0RT
        AdJkG6gq9tBAQp2xTj6Y942Q=
        -----END ENCRYPTED PRIVATE KEY-----
    """.trimIndent()

    private val malformedPem = "-----BEGIN RSA PRIVATE KEY-----\nTHIS IS NOT A VALID KEY\n-----END RSA PRIVATE KEY-----"
    private val notAKey = "This is a plain text file, not a PEM-encoded private key."

    @Test
    fun `loadPrivateKey successfully loads unencrypted PKCS1 RSA key`() {
        writeKeyFile("pkcs1_rsa.pem", rsaPkcs1Unencrypted)
        val manager = createClientCertificateManager("pkcs1_rsa.pem")
        val privateKey = manager.loadPrivateKey()
        assertNotNull(privateKey)
        assertEquals("RSA", privateKey.algorithm)
    }

    @Test
    fun `loadPrivateKey successfully loads unencrypted PKCS8 RSA key`() {
        writeKeyFile("pkcs8_rsa.pem", rsaPkcs8Unencrypted)
        val manager = createClientCertificateManager("pkcs8_rsa.pem")
        val privateKey = manager.loadPrivateKey()
        assertNotNull(privateKey)
        assertEquals("RSA", privateKey.algorithm)
    }

    @Test
    fun `loadPrivateKey successfully loads encrypted PKCS1 RSA key with correct password`() {
        writeKeyFile("pkcs1_rsa_enc.pem", rsaPkcs1Encrypted)
        val manager = createClientCertificateManager("pkcs1_rsa_enc.pem", "testpassword")
        val privateKey = manager.loadPrivateKey()
        assertNotNull(privateKey)
        assertEquals("RSA", privateKey.algorithm)
    }
    
    @Test
    fun `loadPrivateKey successfully loads encrypted PKCS8 RSA key with correct password`() {
        writeKeyFile("pkcs8_rsa_enc.pem", rsaPkcs8Encrypted)
        val manager = createClientCertificateManager("pkcs8_rsa_enc.pem", "testpassword")
        val privateKey = manager.loadPrivateKey()
        assertNotNull(privateKey)
        assertEquals("RSA", privateKey.algorithm)
    }

    @Test
    fun `loadPrivateKey loads unencrypted key even if password is provided`() {
        writeKeyFile("pkcs8_rsa.pem", rsaPkcs8Unencrypted)
        val manager = createClientCertificateManager("pkcs8_rsa.pem", "superfluous_password")
        val privateKey = manager.loadPrivateKey()
        assertNotNull(privateKey)
        assertEquals("RSA", privateKey.algorithm)
    }

    @Test
    fun `loadPrivateKey throws EncryptionException for encrypted PKCS1 key with incorrect password`() {
        writeKeyFile("pkcs1_rsa_enc.pem", rsaPkcs1Encrypted)
        val manager = createClientCertificateManager("pkcs1_rsa_enc.pem", "wrongpassword")
        assertThrows<RuntimeException> { // BouncyCastle specific exceptions are often wrapped
            manager.loadPrivateKey()
        }.also { wrapper ->
             // Check for BouncyCastle's EncryptionException or a similar specific one if not wrapped generically
            val cause = wrapper.cause
            assertTrue(cause is EncryptionException || cause is IOException, "Expected EncryptionException or IOException as cause, got ${cause?.javaClass?.name}")
        }
    }

    @Test
    fun `loadPrivateKey throws PKCSException for encrypted PKCS8 key with incorrect password`() {
        writeKeyFile("pkcs8_rsa_enc.pem", rsaPkcs8Encrypted)
        val manager = createClientCertificateManager("pkcs8_rsa_enc.pem", "wrongpassword")
         assertThrows<RuntimeException> {  // BouncyCastle specific exceptions are often wrapped
            manager.loadPrivateKey()
        }.also { wrapper ->
            val cause = wrapper.cause
             // PKCSException is for failure to decrypt PKCS#8
             // IOException can also be thrown by BouncyCastle for password errors in some flows
            assertTrue(cause is PKCSException || cause is IOException, "Expected PKCSException or IOException as cause, got ${cause?.javaClass?.name}")
        }
    }
    
    @Test
    fun `loadPrivateKey throws IllegalArgumentException for non-existent key file`() {
        val manager = createClientCertificateManager("non_existent_key.pem")
        assertThrows<IllegalArgumentException> {
            manager.loadPrivateKey()
        }
    }

    @Test
    fun `loadPrivateKey throws RuntimeException for malformed PEM file`() {
        writeKeyFile("malformed.pem", malformedPem)
        val manager = createClientCertificateManager("malformed.pem")
        assertThrows<RuntimeException> { // PEMParser throws various exceptions, often wrapped
            manager.loadPrivateKey()
        }
    }
    
    @Test
    fun `loadPrivateKey throws IllegalArgumentException for file that is not a private key`() {
        writeKeyFile("not_a_key.txt", notAKey)
        val manager = createClientCertificateManager("not_a_key.txt")
        assertThrows<IllegalArgumentException> {
            manager.loadPrivateKey()
        }.apply {
            assertTrue(message?.contains("Unsupported PEM object type") == true)
        }
    }
     @Test
    fun `loadPrivateKey throws IllegalArgumentException if clientKeyFile is null`() {
        val manager = createClientCertificateManager(null)
        assertThrows<IllegalArgumentException> {
            manager.loadPrivateKey()
        }.apply {
            assertEquals("Client key file not specified", message)
        }
    }
}
