package org.example.cert

import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.*
import java.io.File
import java.security.cert.Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.net.ssl.X509KeyManager
import org.junit.jupiter.api.Assertions.*
import java.io.FileInputStream
import java.security.cert.CertificateFactory
import java.security.KeyStore
import java.security.PrivateKey
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.mockito.kotlin.any
import java.io.InputStream
import java.security.KeyFactory
import javax.net.ssl.KeyManagerFactory
import io.mockk.*
import org.junit.jupiter.api.AfterEach
import java.security.cert.X509Certificate

class ClientCertificateManagerImplTest {
    private lateinit var clientCertificateManager: ClientCertificateManagerImpl
    private lateinit var mockConfig: SSLTestConfig
    private lateinit var mockCertFile: File
    private lateinit var mockKeyFile: File
    private lateinit var mockCertificate: Certificate
    private lateinit var mockPrivateKey: PrivateKey
    private lateinit var mockFileProvider: FileProvider
    private lateinit var mockInputStream: InputStream

    @BeforeEach
    fun setup() {
        MockKAnnotations.init(this, relaxUnitFun = true)
        mockFileProvider = mockk(relaxed = true)
        clientCertificateManager = ClientCertificateManagerImpl(mockFileProvider)
        mockConfig = mockk(relaxed = true)
        mockCertFile = mockk(relaxed = true)
        mockKeyFile = mockk(relaxed = true)
        mockCertificate = mockk(relaxed = true)
        mockPrivateKey = mockk(relaxed = true)
        mockInputStream = mockk(relaxed = true)
        every { mockConfig.verifyHostname } returns true
        every { mockConfig.clientCertFile } returns "test-cert.pem"
        every { mockConfig.clientKeyFile } returns "test-key.pem"
        every { mockConfig.clientKeyPassword } returns "password"
        every { mockConfig.trustStore } returns "test-truststore.jks"
        every { mockConfig.trustStorePassword } returns "password"
        every { mockFileProvider.exists(any()) } returns true
        every { mockFileProvider.inputStream(any()) } returns mockInputStream
        every { mockFileProvider.readText(any()) } returns """
            -----BEGIN PRIVATE KEY-----
            MIIEvQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALzQ1v1Qw1Qw1Qw1
            Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1
            Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1
            Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1
            Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1Qw1
            -----END PRIVATE KEY-----
        """.trimIndent()

        // Mock CertificateFactory
        mockkStatic(CertificateFactory::class)
        val mockCertFactory = mockk<CertificateFactory>(relaxed = true)
        every { CertificateFactory.getInstance("X.509") } returns mockCertFactory
        every { mockCertFactory.generateCertificate(mockInputStream) } returns mockCertificate

        // Mock KeyStore
        mockkStatic(KeyStore::class)
        val mockKeyStore = mockk<KeyStore>(relaxed = true)
        every { KeyStore.getInstance(any<String>()) } returns mockKeyStore
        every { mockKeyStore.load(any(), any()) } returns Unit
        every { mockKeyStore.setKeyEntry(any(), any(), any(), any()) } returns Unit

        // Mock KeyManagerFactory
        mockkStatic(KeyManagerFactory::class)
        val mockKeyManagerFactory = mockk<KeyManagerFactory>(relaxed = true)
        every { KeyManagerFactory.getInstance(any<String>()) } returns mockKeyManagerFactory
        every { mockKeyManagerFactory.keyManagers } returns arrayOf(mockk(relaxed = true))
        every { mockKeyManagerFactory.init(any(), any()) } returns Unit

        // Mock KeyFactory
        mockkStatic(KeyFactory::class)
        val mockKeyFactory = mockk<KeyFactory>(relaxed = true)
        every { KeyFactory.getInstance(any<String>()) } returns mockKeyFactory
        every { mockKeyFactory.generatePrivate(any()) } returns mockPrivateKey
    }

    @AfterEach
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `test create SSL socket factory`() {
        // Given
        val mockSSLContext = mockk<SSLContext>(relaxed = true)
        val mockSocketFactory = mockk<SSLSocketFactory>(relaxed = true)
        every { mockSSLContext.socketFactory } returns mockSocketFactory
        mockkStatic(SSLContext::class)
        every { SSLContext.getInstance("TLS") } returns mockSSLContext
        every { mockSSLContext.init(any(), any(), any()) } returns Unit

        // When
        val result = clientCertificateManager.createSSLSocketFactory(mockConfig)

        // Then
        assertNotNull(result)
    }

    @Test
    fun `test create SSL context`() {
        // Given
        val mockSSLContext = mockk<SSLContext>(relaxed = true)
        mockkStatic(SSLContext::class)
        every { SSLContext.getInstance("TLS") } returns mockSSLContext
        every { mockSSLContext.init(any(), any(), any()) } returns Unit

        // When
        val result = clientCertificateManager.createSSLContext(mockConfig)

        // Then
        assertNotNull(result)
    }

    @Test
    fun `test create trust managers`() {
        // When
        val result = clientCertificateManager.createTrustManagers(mockConfig)

        // Then
        assertTrue(result.isNotEmpty())
        assertTrue(result[0] is X509TrustManager)
    }

    @Test
    fun `test create trust all manager`() {
        // When
        val result = clientCertificateManager.createTrustAllManager()

        // Then
        assertNotNull(result)
        assertTrue(result is X509TrustManager)
    }

    @Test
    fun `test create key managers`() {
        // Given
        val config = SSLTestConfig(
            url = "https://example.com",
            clientCertFile = "dummyCertFile",
            clientKeyFile = "dummyKeyFile",
            clientKeyPassword = "password"
        )
        val mockKeyStore = mockk<KeyStore>(relaxed = true)
        val mockPrivateKey = mockk<PrivateKey>(relaxed = true)
        val mockCertificate = mockk<X509Certificate>(relaxed = true)
        val mockCertificateChain = arrayOf(mockCertificate)
        val mockKeyManagerFactory = mockk<KeyManagerFactory>(relaxed = true)
        val mockKeyManager = mockk<X509KeyManager>(relaxed = true)
        val mockKeyManagers = arrayOf(mockKeyManager)

        // Mock KeyStore
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any()) } returns mockKeyStore
        every { mockKeyStore.getKey(any(), any()) } returns mockPrivateKey
        every { mockKeyStore.getCertificateChain(any()) } returns mockCertificateChain

        // Mock KeyManagerFactory
        mockkStatic(KeyManagerFactory::class)
        every { KeyManagerFactory.getInstance(any()) } returns mockKeyManagerFactory
        every { mockKeyManagerFactory.keyManagers } returns mockKeyManagers
        every { mockKeyManagerFactory.init(any(), any()) } just Runs

        // When
        val keyManagers = clientCertificateManager.createKeyManagers(config)

        // Then
        assertNotNull(keyManagers)
        assertTrue(keyManagers.isNotEmpty())
        assertTrue(keyManagers[0] is X509KeyManager)
    }
}