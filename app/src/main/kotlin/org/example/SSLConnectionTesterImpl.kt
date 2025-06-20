package org.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.example.exception.SSLTestException
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
 * SSL 连接测试核心实现。
 * 负责建立 SSL/TLS 连接并收集连接信息。
 */
class SSLConnectionTesterImpl {
    /**
     * 测试指定主机和端口的 SSL/TLS 连接。
     * @param host 目标主机
     * @param port 目标端口
     * @param config 测试配置
     * @return 测试结果，成功返回 SSLConnection，失败返回异常
     */
    suspend fun testConnection(
        host: String,
        port: Int,
        config: SSLTestConfig,
    ): Result<SSLConnection> =
        withContext(Dispatchers.IO) {
            val startTime = Instant.now()

            runCatching {
                val socket = Socket()
                try {
                    socket.soTimeout = config.connectionTimeout
                    withTimeout(config.connectionTimeout.toLong()) {
                        socket.connect(InetSocketAddress(host, port), config.connectionTimeout)
                    }

                    val sslContext = initializeSSL().getOrThrow()
                    val sslSocket =
                        sslContext.socketFactory.createSocket(
                            socket,
                            host,
                            port,
                            true,
                        ) as SSLSocket

                    try {
                        sslSocket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
                        sslSocket.soTimeout = config.connectionTimeout

                        withTimeout(config.connectionTimeout.toLong()) {
                            sslSocket.startHandshake()
                        }

                        val endTime = Instant.now()
                        val handshakeTime = Duration.between(startTime, endTime)
                        val session = sslSocket.session

                        val certificates =
                            runCatching {
                                session.peerCertificates.map { cert -> cert as X509Certificate }
                            }.getOrDefault(emptyList())

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
                        throw when (e) {
                            is SSLHandshakeException ->
                                SSLTestException.HandshakeError(
                                    host = host,
                                    port = port,
                                    message = "SSL Handshake failed: ${e.message}",
                                    cause = e,
                                )
                            is SSLProtocolException ->
                                SSLTestException.HandshakeError(
                                    host = host,
                                    port = port,
                                    message = "SSL Protocol error: ${e.message}",
                                    cause = e,
                                )
                            is SocketTimeoutException ->
                                SSLTestException.HandshakeError(
                                    host = host,
                                    port = port,
                                    message = "SSL Handshake timeout",
                                    cause = e,
                                )
                            else ->
                                SSLTestException.HandshakeError(
                                    host = host,
                                    port = port,
                                    message = "SSL Error: ${e.message}",
                                    cause = e,
                                )
                        }
                    } finally {
                        runCatching { sslSocket.close() }
                    }
                } catch (e: Exception) {
                    runCatching { socket.close() }
                    throw when (e) {
                        is UnknownHostException ->
                            SSLTestException.ConnectionError(
                                host = host,
                                port = port,
                                message = "Unknown host: ${e.message}",
                                cause = e,
                            )
                        is SocketTimeoutException ->
                            SSLTestException.ConnectionError(
                                host = host,
                                port = port,
                                message = "Connection timeout",
                                cause = e,
                            )
                        is IOException ->
                            SSLTestException.ConnectionError(
                                host = host,
                                port = port,
                                message = "Connection failed: ${e.message ?: "Connection refused"}",
                                cause = e,
                            )
                        is SSLTestException -> e
                        else ->
                            SSLTestException.ConnectionError(
                                host = host,
                                port = port,
                                message = "Unknown error: ${e.message ?: e.toString()}",
                                cause = e,
                            )
                    }
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
                                )
                        },
                    )
                },
            )
        }

    private fun initializeSSL(): Result<SSLContext> =
        runCatching {
            val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustManagerFactory.init(null as KeyStore?)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, trustManagerFactory.trustManagers, null)
            sslContext
        }
}
