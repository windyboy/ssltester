package org.example.service

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.example.SSLTestConfig
import org.example.model.SSLConnection
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

class SSLConnectionTesterImpl : SSLConnectionTester {
    override suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): SSLConnection {
        return withContext(Dispatchers.IO) {
            val startTime = Instant.now()
            var socket: Socket? = null
            var sslSocket: SSLSocket? = null

            try {
                val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                trustManagerFactory.init(null as KeyStore?)
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, trustManagerFactory.trustManagers, null)
                val socketFactory = sslContext.socketFactory

                socket = Socket()
                socket.soTimeout = config.connectionTimeout

                try {
                    withTimeout(config.connectionTimeout.toLong()) {
                        socket.connect(InetSocketAddress(host, port), config.connectionTimeout)
                    }

                    sslSocket = socketFactory.createSocket(socket, host, port, true) as SSLSocket
                    sslSocket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
                    sslSocket.soTimeout = config.connectionTimeout

                    try {
                        withTimeout(config.connectionTimeout.toLong()) {
                            sslSocket.startHandshake()
                        }

                        val endTime = Instant.now()
                        val handshakeTime = Duration.between(startTime, endTime)
                        val session = sslSocket.session

                        val certificates =
                            try {
                                session.peerCertificates.map { it as X509Certificate }
                            } catch (e: Exception) {
                                emptyList()
                            }

                        SSLConnection(
                            host = host,
                            port = port,
                            protocol = session.protocol,
                            cipherSuite = session.cipherSuite,
                            handshakeTime = handshakeTime,
                            isSecure = true,
                            certificateChain = certificates,
                        )
                    } catch (e: Exception) {
                        createFailedConnection(
                            host,
                            port,
                            startTime,
                            when (e) {
                                is SSLHandshakeException -> "SSL Handshake failed: ${e.message}"
                                is SSLProtocolException -> "SSL Protocol error: ${e.message}"
                                is SocketTimeoutException -> "SSL Handshake timeout"
                                else -> "SSL Error: ${e.message}"
                            },
                        )
                    }
                } catch (e: Exception) {
                    createFailedConnection(
                        host,
                        port,
                        startTime,
                        when (e) {
                            is SocketTimeoutException -> "Connection timeout"
                            is IOException -> "Connection failed: ${e.message}"
                            else -> "Error: ${e.message}"
                        },
                    )
                }
            } catch (e: Exception) {
                createFailedConnection(host, port, startTime, "Initialization error: ${e.message}")
            } finally {
                try {
                    sslSocket?.close()
                } catch (_: Exception) {
                }
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun createFailedConnection(
        host: String,
        port: Int,
        startTime: Instant,
        errorMessage: String,
    ): SSLConnection =
        SSLConnection(
            host = host,
            port = port,
            protocol = "Unknown ($errorMessage)",
            cipherSuite = "Unknown",
            handshakeTime = Duration.between(startTime, Instant.now()),
            isSecure = false,
            certificateChain = emptyList(),
        )
}
