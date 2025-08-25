package org.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.example.exception.SSLTestException
import org.example.factory.ComponentFactoryManager
import org.example.model.SSLConnection
import org.example.model.SSLTestConfig
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/**
 * SSL 连接测试默认实现。
 * 负责建立 SSL/TLS 连接并收集连接信息。
 */
class DefaultSSLConnectionTester : SSLConnectionTester {
    private val certificateValidator: CertificateValidator = ComponentFactoryManager.getFactory().createCertificateValidator()

    /**
     * 测试指定主机和端口的 SSL/TLS 连接。
     * @param host 目标主机
     * @param port 目标端口
     * @param config 测试配置
     * @return 测试结果，成功返回 SSLConnection，失败返回异常
     */
    override suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection> =
        withContext(Dispatchers.IO) {
            val startTime = Instant.now()

            runCatching {
                // Use structured resource management with Kotlin's 'use' function
                Socket().use { socket ->
                    socket.soTimeout = config.readTimeout

                    // Establish TCP connection with timeout
                    establishTcpConnection(socket, host, port, config.connectionTimeout)

                    // Create SSL context and socket
                    val sslContext = initializeSSL().getOrThrow()
                    val sslSocket = createSSLSocket(sslContext, socket, host, port)

                    // Configure SSL socket
                    configureSSLSocket(sslSocket, config)

                    // Perform SSL handshake with timeout
                    performSSLHandshake(sslSocket, config.handshakeTimeout)

                    // Extract connection information
                    extractConnectionInfo(sslSocket, host, port, startTime, config)
                }
            }.fold(
                onSuccess = { Result.success(it) },
                onFailure = { e ->
                    Result.failure(
                        when (e) {
                            is SSLTestException -> e
                            else ->
                                SSLTestException.ConfigurationError(
                                    message = "SSL initialization error: ${e.localizedMessage ?: e.toString()}",
                                    cause = e,
                                    configField = "SSL_INITIALIZATION",
                                )
                        },
                    )
                },
            )
        }

    /**
     * 建立TCP连接。
     */
    private suspend fun establishTcpConnection(
        socket: Socket,
        host: String,
        port: Int,
        timeout: Int,
    ) {
        try {
            withTimeout(timeout.toLong()) {
                socket.connect(InetSocketAddress(host, port), timeout)
            }
        } catch (e: Exception) {
            throw when (e) {
                is UnknownHostException ->
                    SSLTestException.ConnectionError(
                        host = host,
                        port = port,
                        message = "${SSLConstants.ERROR_UNKNOWN_HOST}: ${e.message}",
                        cause = e,
                        connectionType = SSLTestException.ConnectionType.TCP_CONNECTION,
                    )
                is SocketTimeoutException ->
                    SSLTestException.TimeoutError(
                        host = host,
                        port = port,
                        message = SSLConstants.ERROR_CONNECTION_TIMEOUT,
                        cause = e,
                        timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                        timeoutValue = timeout.toLong(),
                    )
                is IOException ->
                    SSLTestException.ConnectionError(
                        host = host,
                        port = port,
                        message = "${SSLConstants.ERROR_CONNECTION_FAILED}: ${e.message ?: "Connection refused"}",
                        cause = e,
                        connectionType = SSLTestException.ConnectionType.TCP_CONNECTION,
                    )
                else ->
                    SSLTestException.ConnectionError(
                        host = host,
                        port = port,
                        message = "TCP connection failed: ${e.message ?: e.toString()}",
                        cause = e,
                        connectionType = SSLTestException.ConnectionType.TCP_CONNECTION,
                    )
            }
        }
    }

    /**
     * 创建SSL Socket。
     */
    private fun createSSLSocket(
        sslContext: SSLContext,
        socket: Socket,
        host: String,
        port: Int,
    ): SSLSocket {
        return try {
            sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket
        } catch (e: Exception) {
            throw SSLTestException.ConfigurationError(
                message = "Failed to create SSL socket: ${e.message}",
                cause = e,
                configField = "SSL_SOCKET_CREATION",
            )
        }
    }

    /**
     * 配置SSL Socket。
     */
    private fun configureSSLSocket(
        sslSocket: SSLSocket,
        config: SSLTestConfig,
    ) {
        try {
            sslSocket.enabledProtocols = SSLConstants.DEFAULT_ENABLED_PROTOCOLS
            sslSocket.soTimeout = config.readTimeout
        } catch (e: Exception) {
            throw SSLTestException.ConfigurationError(
                message = "Failed to configure SSL socket: ${e.message}",
                cause = e,
                configField = "SSL_SOCKET_CONFIGURATION",
            )
        }
    }

    /**
     * 执行SSL握手。
     */
    private suspend fun performSSLHandshake(
        sslSocket: SSLSocket,
        handshakeTimeout: Int,
    ) {
        try {
            withTimeout(handshakeTimeout.toLong()) {
                sslSocket.startHandshake()
            }
        } catch (e: Exception) {
            throw when (e) {
                is SSLHandshakeException ->
                    SSLTestException.HandshakeError(
                        host = "unknown",
                        port = -1,
                        message = "${SSLConstants.ERROR_SSL_HANDSHAKE}: ${e.message}",
                        cause = e,
                    )
                is SSLProtocolException ->
                    SSLTestException.HandshakeError(
                        host = "unknown",
                        port = -1,
                        message = "${SSLConstants.ERROR_SSL_PROTOCOL}: ${e.message}",
                        cause = e,
                    )
                is SocketTimeoutException ->
                    SSLTestException.TimeoutError(
                        host = "unknown",
                        port = -1,
                        message = "SSL Handshake timeout",
                        cause = e,
                        timeoutType = SSLTestException.TimeoutType.HANDSHAKE_TIMEOUT,
                        timeoutValue = handshakeTimeout.toLong(),
                    )
                else ->
                    SSLTestException.HandshakeError(
                        host = "unknown",
                        port = -1,
                        message = "SSL Error: ${e.message}",
                        cause = e,
                    )
            }
        }
    }

    /**
     * 提取连接信息。
     */
    private suspend fun extractConnectionInfo(
        sslSocket: SSLSocket,
        host: String,
        port: Int,
        startTime: Instant,
        config: SSLTestConfig,
    ): SSLConnection {
        val endTime = Instant.now()
        val handshakeTime = Duration.between(startTime, endTime)
        val session = sslSocket.session

        val certificates = extractCertificates(session)
        val certificateValidation =
            if (certificates.isNotEmpty() && config.enableOCSPValidation) {
                certificateValidator.validateCertificateChain(certificates)
            } else {
                null
            }

        return SSLConnection(
            host = host,
            port = port,
            protocol = session.protocol,
            cipherSuite = session.cipherSuite,
            handshakeTime = handshakeTime,
            isSecure = true,
            certificateChain = certificates,
            certificateValidation = certificateValidation,
        )
    }

    /**
     * 提取证书链。
     */
    private fun extractCertificates(session: javax.net.ssl.SSLSession): List<X509Certificate> {
        return runCatching {
            session.peerCertificates?.mapNotNull { cert ->
                cert as? X509Certificate
            } ?: emptyList()
        }.getOrElse {
            emptyList<X509Certificate>()
        }
    }

    /**
     * 初始化SSL上下文。
     */
    private fun initializeSSL(): Result<SSLContext> =
        runCatching {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            val sslContext = SSLContext.getInstance(SSLConstants.DEFAULT_SSL_CONTEXT_PROTOCOL)
            sslContext.init(null, trustManagerFactory.trustManagers, null)
            sslContext
        }.onFailure { e ->
            throw SSLTestException.ConfigurationError(
                message = "Failed to initialize SSL context: ${e.message}",
                cause = e,
                configField = "SSL_CONTEXT_INITIALIZATION",
            )
        }
}
