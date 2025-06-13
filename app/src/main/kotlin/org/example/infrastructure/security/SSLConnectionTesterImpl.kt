package org.example.infrastructure.security

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.example.domain.model.SSLConnection
import org.example.domain.service.SSLConnectionTester
import org.example.config.SSLTestConfig
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import java.net.Socket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import java.io.IOException

class SSLConnectionTesterImpl : SSLConnectionTester {
    override suspend fun testConnection(host: String, port: Int, config: SSLTestConfig): SSLConnection {
        return withContext(Dispatchers.IO) {
            val startTime = Instant.now()
            var socket: Socket? = null
            var sslSocket: SSLSocket? = null
            
            try {
                // 初始化SSL上下文
                val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                trustManagerFactory.init(null as KeyStore?)
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, trustManagerFactory.trustManagers, null)
                val socketFactory = sslContext.socketFactory

                // 创建普通Socket并设置连接超时
                socket = Socket()
                socket.soTimeout = config.connectionTimeout
                
                try {
                    withTimeout(config.connectionTimeout.toLong()) {
                        socket.connect(InetSocketAddress(host, port), config.connectionTimeout)
                    }
                    
                    // 升级为SSL连接
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
                        
                        // 获取证书链
                        val certificates = try {
                            val certs = session.peerCertificates
                            println("Debug: Found ${certs.size} certificates")
                            certs.map { cert ->
                                try {
                                    cert as X509Certificate
                                } catch (e: Exception) {
                                    println("Debug: Failed to cast certificate: ${e.message}")
                                    null
                                }
                            }.filterNotNull()
                        } catch (e: Exception) {
                            println("Debug: Failed to get certificates: ${e.message}")
                            emptyList()
                        }
                        
                        println("Debug: Successfully processed ${certificates.size} certificates")
                        
                        // 创建连接对象
                        val connection = SSLConnection(
                            host = host,
                            port = port,
                            protocol = session.protocol,
                            cipherSuite = session.cipherSuite,
                            handshakeTime = handshakeTime,
                            isSecure = true,
                            certificateChain = certificates
                        )
                        
                        // 验证证书链是否正确传递
                        println("Debug: Connection object has ${connection.certificateChain.size} certificates")
                        
                        connection
                    } catch (e: SSLHandshakeException) {
                        createFailedConnection(host, port, startTime, "SSL Handshake failed: ${e.message}")
                    } catch (e: SSLProtocolException) {
                        createFailedConnection(host, port, startTime, "SSL Protocol error: ${e.message}")
                    } catch (e: SocketTimeoutException) {
                        createFailedConnection(host, port, startTime, "SSL Handshake timeout")
                    } catch (e: Exception) {
                        createFailedConnection(host, port, startTime, "SSL Error: ${e.message}")
                    }
                } catch (e: SocketTimeoutException) {
                    createFailedConnection(host, port, startTime, "Connection timeout")
                } catch (e: IOException) {
                    createFailedConnection(host, port, startTime, "Connection failed: ${e.message}")
                } catch (e: Exception) {
                    createFailedConnection(host, port, startTime, "Error: ${e.message}")
                }
            } catch (e: Exception) {
                createFailedConnection(host, port, startTime, "Initialization error: ${e.message}")
            } finally {
                try {
                    sslSocket?.close()
                } catch (e: Exception) {
                    // Ignore close errors
                }
                try {
                    socket?.close()
                } catch (e: Exception) {
                    // Ignore close errors
                }
            }
        }
    }
    
    private fun createFailedConnection(
        host: String,
        port: Int,
        startTime: Instant,
        errorMessage: String
    ): SSLConnection {
        return SSLConnection(
            host = host,
            port = port,
            protocol = "Unknown",
            cipherSuite = "Unknown",
            handshakeTime = Duration.between(startTime, Instant.now()),
            isSecure = false,
            certificateChain = emptyList()
        )
    }
} 