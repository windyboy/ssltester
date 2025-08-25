package org.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.example.exception.SSLTestException
import org.example.logging.SSLTestContext
import org.example.logging.StructuredLogger
import org.example.metrics.PerformanceMetrics
import org.example.model.SSLConnection
import org.example.model.SSLTestConfig
import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.time.Duration
import java.time.Instant
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * 默认SSL连接测试器实现。
 * 使用新的类型安全结果和结构化日志记录。
 */
class DefaultSSLConnectionTester(
    private val certificateValidator: CertificateValidator = CertificateValidator(),
    private val logger: StructuredLogger = StructuredLogger.create(),
    private val performanceMetrics: PerformanceMetrics = PerformanceMetrics(),
) : SSLConnectionTester {
    override suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection> =
        withContext(Dispatchers.IO) {
            // 创建测试上下文
            val context =
                SSLTestContext(
                    host = host,
                    port = port,
                    connectionTimeout = config.connectionTimeout,
                    readTimeout = config.readTimeout,
                    handshakeTimeout = config.handshakeTimeout,
                    format = config.format,
                    outputFile = config.outputFile,
                    enableHostnameVerification = config.enableHostnameVerification,
                    enableOCSPValidation = config.enableOCSPValidation,
                    maxRetries = config.maxRetries,
                    retryDelay = config.retryDelay,
                )

            // 记录测试开始
            logger.logTestStart(context)
            performanceMetrics.addCheckpoint("test_start")

            return@withContext try {
                // 执行SSL测试
                val result = performSSLTest(context, config)

                // 记录测试完成
                performanceMetrics.addCheckpoint("test_complete")

                // 记录性能指标
                val totalDuration = performanceMetrics.getTotalDuration()
                logger.logPerformanceMetrics(context, performanceMetrics.getAllMetrics())

                Result.success(result)
            } catch (e: Exception) {
                // 记录测试失败
                performanceMetrics.addCheckpoint("test_complete")
                val totalDuration = performanceMetrics.getTotalDuration()

                val sslException =
                    when (e) {
                        is SSLTestException -> e
                        else ->
                            SSLTestException.ConfigurationError(
                                message = "Unexpected error during SSL test: ${e.message}",
                                cause = e,
                            )
                    }

                logger.logTestFailure(
                    context,
                    org.example.model.SSLTestResult.Failure(
                        error = sslException,
                        host = host,
                        port = port,
                        testDuration = totalDuration,
                        timestamp = Instant.now(),
                    ),
                )

                Result.failure(sslException)
            }
        }

    /**
     * 执行SSL测试。
     */
    private suspend fun performSSLTest(
        context: SSLTestContext,
        config: SSLTestConfig,
    ): SSLConnection {
        val startTime = Instant.now()

        return try {
            Socket().use { socket ->
                socket.soTimeout = config.readTimeout

                // 建立TCP连接
                val tcpStartTime = Instant.now()
                establishTcpConnection(socket, context.host, context.port, config.connectionTimeout.toLong())
                val tcpDuration = Duration.between(tcpStartTime, Instant.now())
                logger.logConnectionEstablished(context, tcpDuration)
                performanceMetrics.recordMetric("tcp_connection_time", tcpDuration)

                // 创建SSL上下文和Socket
                val sslContext = initializeSSL().getOrThrow()
                val sslSocket = createSSLSocket(sslContext, socket, context.host, context.port)

                // 配置SSL Socket
                configureSSLSocket(sslSocket, config)

                // 执行SSL握手
                val handshakeStartTime = Instant.now()
                logger.logHandshakeStart(context)
                performanceMetrics.addCheckpoint("ssl_handshake")

                performSSLHandshake(sslSocket, config.handshakeTimeout.toLong())

                val handshakeDuration = Duration.between(handshakeStartTime, Instant.now())
                logger.logHandshakeComplete(
                    context,
                    handshakeDuration,
                    sslSocket.session.protocol,
                    sslSocket.session.cipherSuite,
                )
                performanceMetrics.recordMetric("ssl_handshake_time", handshakeDuration)

                // 提取连接信息
                val connection = extractConnectionInfo(sslSocket, context.host, context.port, startTime, config, context)

                // 记录测试成功
                val totalDuration = Duration.between(startTime, Instant.now())
                val successResult =
                    org.example.model.SSLTestResult.Success(
                        connection = connection,
                        testDuration = totalDuration,
                        timestamp = Instant.now(),
                    )

                logger.logTestSuccess(context, successResult)
                connection
            }
        } catch (e: SSLTestException) {
            // SSL测试异常
            val totalDuration = Duration.between(startTime, Instant.now())

            when (e) {
                is SSLTestException.TimeoutError -> {
                    logger.logTestTimeout(
                        context,
                        org.example.model.SSLTestResult.Timeout(
                            host = context.host,
                            port = context.port,
                            timeoutType = e.timeoutType,
                            timeoutValue = e.timeoutValue,
                            testDuration = totalDuration,
                            timestamp = Instant.now(),
                        ),
                    )

                    throw e
                }
                else -> {
                    logger.logTestFailure(
                        context,
                        org.example.model.SSLTestResult.Failure(
                            error = e,
                            host = context.host,
                            port = context.port,
                            testDuration = totalDuration,
                            timestamp = Instant.now(),
                        ),
                    )

                    throw e
                }
            }
        }
    }

    /**
     * 建立TCP连接。
     */
    private suspend fun establishTcpConnection(
        socket: Socket,
        host: String,
        port: Int,
        timeout: Long,
    ) {
        try {
            socket.connect(java.net.InetSocketAddress(host, port), timeout.toInt())
        } catch (e: Exception) {
            when (e) {
                is UnknownHostException ->
                    throw SSLTestException.ConnectionError(
                        host = host,
                        port = port,
                        message = "${SSLConstants.ERROR_UNKNOWN_HOST}: ${e.message}",
                        cause = e,
                        connectionType = SSLTestException.ConnectionType.TCP_CONNECTION,
                    )
                is SocketTimeoutException ->
                    throw SSLTestException.TimeoutError(
                        host = host,
                        port = port,
                        message =
                            SSLTestException.createTimeoutMessage(
                                SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                                host,
                                port,
                                timeout,
                            ),
                        cause = e,
                        timeoutType = SSLTestException.TimeoutType.CONNECTION_TIMEOUT,
                        timeoutValue = timeout.toLong(),
                    )
                is IOException ->
                    throw SSLTestException.ConnectionError(
                        host = host,
                        port = port,
                        message = "${SSLConstants.ERROR_CONNECTION_FAILED}: ${e.message ?: "Connection refused"}",
                        cause = e,
                        connectionType = SSLTestException.ConnectionType.TCP_CONNECTION,
                    )
                else ->
                    throw SSLTestException.ConnectionError(
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
            val sslSocketFactory = sslContext.socketFactory as SSLSocketFactory
            sslSocketFactory.createSocket(socket, host, port, true) as SSLSocket
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
        handshakeTimeout: Long,
    ) {
        try {
            // 使用协程超时
            withTimeout(handshakeTimeout.toLong()) {
                sslSocket.startHandshake()
            }
        } catch (e: Exception) {
            when (e) {
                is SSLHandshakeException ->
                    throw SSLTestException.HandshakeError(
                        host = "",
                        port = -1,
                        message = "${SSLConstants.ERROR_SSL_HANDSHAKE}: ${e.message}",
                        cause = e,
                    )
                is SSLProtocolException ->
                    throw SSLTestException.HandshakeError(
                        host = "",
                        port = -1,
                        message = "${SSLConstants.ERROR_SSL_PROTOCOL}: ${e.message}",
                        cause = e,
                    )
                is kotlinx.coroutines.TimeoutCancellationException ->
                    throw SSLTestException.TimeoutError(
                        host = "",
                        port = -1,
                        message =
                            SSLTestException.createTimeoutMessage(
                                SSLTestException.TimeoutType.HANDSHAKE_TIMEOUT,
                                "",
                                -1,
                                handshakeTimeout,
                            ),
                        timeoutType = SSLTestException.TimeoutType.HANDSHAKE_TIMEOUT,
                        timeoutValue = handshakeTimeout.toLong(),
                    )
                else ->
                    throw SSLTestException.HandshakeError(
                        host = "",
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
    private fun extractConnectionInfo(
        sslSocket: SSLSocket,
        host: String,
        port: Int,
        startTime: Instant,
        config: SSLTestConfig,
        context: SSLTestContext,
    ): SSLConnection {
        val endTime = Instant.now()
        val session = sslSocket.session
        val handshakeTime = Duration.between(startTime, endTime)

        val certificates = extractCertificates(session)
        val certificateValidation =
            if (certificates.isNotEmpty() && config.enableOCSPValidation) {
                val validationStartTime = Instant.now()
                performanceMetrics.addCheckpoint("certificate_validation")

                // 使用协程运行证书验证
                runBlocking {
                    certificateValidator.validateCertificateChain(certificates)
                }
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
     * 提取证书。
     */
    private fun extractCertificates(session: javax.net.ssl.SSLSession): List<java.security.cert.X509Certificate> {
        return runCatching {
            session.peerCertificates.mapNotNull { cert ->
                cert as? java.security.cert.X509Certificate
            }
        }.getOrElse {
            emptyList<java.security.cert.X509Certificate>()
        }
    }

    /**
     * 初始化SSL上下文。
     */
    private fun initializeSSL(): Result<SSLContext> {
        return runCatching {
            SSLContext.getInstance("TLS").apply {
                init(null, null, null)
            }
        }.onFailure { e ->
            throw SSLTestException.ConfigurationError(
                message = "Failed to initialize SSL context: ${e.message}",
                cause = e,
                configField = "SSL_CONTEXT_INITIALIZATION",
            )
        }
    }
}
