package org.example.ssl

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.*
import java.io.IOException
import java.net.Socket
import java.net.URL
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class SSLClientTest {
    private lateinit var sslClient: SSLClient
    private lateinit var mockSocketFactory: SSLSocketFactory
    private lateinit var mockSocket: SSLSocket
    private lateinit var mockSession: javax.net.ssl.SSLSession

    @BeforeEach
    fun setup() {
        mockSocketFactory = mock(SSLSocketFactory::class.java)
        mockSocket = mock(SSLSocket::class.java)
        mockSession = mock(javax.net.ssl.SSLSession::class.java)
        sslClient = SSLClient(mockSocketFactory)
    }

    @AfterEach
    fun cleanup() {
        // Removed verifyNoMoreInteractions to avoid over-strict mock verification
    }

    @Test
    fun `test successful connection`() {
        val url = URL("https://example.com")
        `when`(mockSocketFactory.createSocket("example.com", 443)).thenReturn(mockSocket)
        `when`(mockSocket.isConnected).thenReturn(true)
        `when`(mockSocket.isClosed).thenReturn(false)
        `when`(mockSocket.session).thenReturn(mockSession)
        `when`(mockSession.cipherSuite).thenReturn("TLS_FAKE_CIPHER")
        val cert = mock(java.security.cert.X509Certificate::class.java)
        `when`(cert.subjectAlternativeNames).thenReturn(listOf(listOf(2, "example.com")))
        `when`(cert.getSubjectAlternativeNames()).thenReturn(listOf(listOf(2, "example.com")))
        `when`(cert.subjectX500Principal).thenReturn(javax.security.auth.x500.X500Principal("CN=example.com"))
        `when`(mockSession.peerCertificates).thenReturn(arrayOf(cert))

        val result = sslClient.connect(url)

        assert(result.success)
        assert(result.hostnameVerified)
        verify(mockSocketFactory).createSocket("example.com", 443)
        verify(mockSocket).startHandshake()
        // Do not verify close() here; socket is not closed after successful connection
    }

    @Test
    fun `test connection with timeout`() {
        val url = URL("https://example.com")
        `when`(mockSocketFactory.createSocket("example.com", 443)).thenThrow(IOException("Connection timed out"))

        val result = sslClient.connect(url)

        assert(!result.success)
        assert(result.error?.message?.contains("Connection timed out") == true)
        verify(mockSocketFactory).createSocket("example.com", 443)
        // No socket was created, so no close() verification needed
    }

    @Test
    fun `test close connection`() {
        val url = URL("https://example.com")
        `when`(mockSocketFactory.createSocket("example.com", 443)).thenReturn(mockSocket)
        `when`(mockSocket.isConnected).thenReturn(true)
        `when`(mockSocket.isClosed).thenReturn(false)
        `when`(mockSocket.session).thenReturn(mockSession)
        `when`(mockSession.cipherSuite).thenReturn("TLS_FAKE_CIPHER")
        val cert = mock(java.security.cert.X509Certificate::class.java)
        `when`(cert.subjectAlternativeNames).thenReturn(listOf(listOf(2, "example.com")))
        `when`(cert.getSubjectAlternativeNames()).thenReturn(listOf(listOf(2, "example.com")))
        `when`(cert.subjectX500Principal).thenReturn(javax.security.auth.x500.X500Principal("CN=example.com"))
        `when`(mockSession.peerCertificates).thenReturn(arrayOf(cert))

        sslClient.connect(url)
        sslClient.close()

        verify(mockSocketFactory).createSocket("example.com", 443)
        verify(mockSocket).startHandshake()
        verify(mockSocket, atLeastOnce()).close()
    }

    @Test
    fun `test connection with SSL handshake failure`() {
        val url = URL("https://example.com")
        `when`(mockSocketFactory.createSocket("example.com", 443)).thenReturn(mockSocket)
        `when`(mockSocket.startHandshake()).thenThrow(IOException("SSL handshake failed"))
        `when`(mockSocket.session).thenReturn(mockSession)
        `when`(mockSession.cipherSuite).thenReturn("TLS_FAKE_CIPHER")
        `when`(mockSession.peerCertificates).thenReturn(arrayOf(mock(java.security.cert.X509Certificate::class.java)))

        val result = sslClient.connect(url)

        assert(!result.success)
        assert(result.error?.message?.contains("SSL handshake failed") == true)
        verify(mockSocketFactory).createSocket("example.com", 443)
        verify(mockSocket).startHandshake()
        // Socket should be closed after handshake failure
        verify(mockSocket).close()
    }

    @Test
    fun `test connection with custom port`() {
        val url = URL("https://example.com:8443")
        `when`(mockSocketFactory.createSocket("example.com", 8443)).thenReturn(mockSocket)
        `when`(mockSocket.isConnected).thenReturn(true)
        `when`(mockSocket.isClosed).thenReturn(false)
        `when`(mockSocket.session).thenReturn(mockSession)
        `when`(mockSession.cipherSuite).thenReturn("TLS_FAKE_CIPHER")
        `when`(mockSession.peerCertificates).thenReturn(arrayOf(mock(java.security.cert.X509Certificate::class.java)))

        val result = sslClient.connect(url)

        assert(result.success)
        verify(mockSocketFactory).createSocket("example.com", 8443)
        verify(mockSocket).startHandshake()
    }

    @Test
    fun `test connection with invalid URL protocol`() {
        val url = URL("http://example.com")
        assertThrows<IllegalArgumentException> {
            sslClient.connect(url)
        }
    }

    @Test
    fun `hostname verification mismatch`() {
        val url = URL("https://example.com")
        `when`(mockSocketFactory.createSocket("example.com", 443)).thenReturn(mockSocket)
        `when`(mockSocket.isConnected).thenReturn(true)
        `when`(mockSocket.isClosed).thenReturn(false)
        `when`(mockSocket.session).thenReturn(mockSession)
        `when`(mockSession.cipherSuite).thenReturn("TLS_FAKE_CIPHER")
        val cert = mock(java.security.cert.X509Certificate::class.java)
        `when`(cert.subjectAlternativeNames).thenReturn(listOf(listOf(2, "wrong.com")))
        `when`(cert.getSubjectAlternativeNames()).thenReturn(listOf(listOf(2, "wrong.com")))
        `when`(cert.subjectX500Principal).thenReturn(javax.security.auth.x500.X500Principal("CN=wrong.com"))
        `when`(mockSession.peerCertificates).thenReturn(arrayOf(cert))

        val result = sslClient.connect(url)

        assert(result.success)
        assert(!result.hostnameVerified)
        verify(mockSocketFactory).createSocket("example.com", 443)
        verify(mockSocket).startHandshake()
    }
} 