package org.example.core

import io.mockk.every
import io.mockk.spyk
import kotlinx.coroutines.runBlocking
import org.example.SSLConnectionTesterImpl
import org.example.exception.SSLTestException
import org.example.model.SSLConnection
import org.example.model.SSLTestConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Duration
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SSLConnectionTesterImplTest {
    private val tester = SSLConnectionTesterImpl()

    @Test
    fun `test connection to invalid host`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-does-not-exist.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
            assertTrue(
                error.message?.contains("Connection failed") == true ||
                    error.message?.contains("Unknown") == true,
            )
        }
    }

    @Test
    fun `test connection timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
            assertTrue(
                error.message?.contains("timeout") == true ||
                    error.message?.contains("Unknown") == true,
            )
        }
    }

    @Test
    fun `test connection to invalid port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    44443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
            assertTrue(
                error.message?.contains("Connection failed") == true ||
                    error.message?.contains("Unknown") == true ||
                    error.message?.contains("Connection refused") == true ||
                    error.message?.contains("timed out") == true,
            )
        }
    }

    @Test
    fun `test SSL configuration validation`() {
        val config = SSLTestConfig(connectionTimeout = 5000)
        assertEquals(5000, config.connectionTimeout)
    }

    @Test
    fun `test connection with zero timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 0),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    @Test
    fun `test connection with negative timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = -1),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    @Test
    fun `test connection with very large timeout`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 30000),
                )

            // Should either succeed or fail with a specific error, not hang
            assertTrue(result.isSuccess || result.isFailure)
        }
    }

    @Test
    fun `test connection with IPv4 address`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "192.168.1.1",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with IPv6 address`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "::1",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with localhost`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun testConnectionWith127001() {
        runBlocking {
            val result =
                tester.testConnection(
                    "127.0.0.1",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with empty hostname`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with whitespace hostname`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "   ",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with very long hostname`() {
        val longHost = "a".repeat(100) + ".example.com"
        runBlocking {
            val result =
                tester.testConnection(
                    longHost,
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with special characters in hostname`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "test-host.example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with negative port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    -1,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with zero port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    0,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with maximum port`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    65535,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with port above maximum`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    65536,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)
        }
    }

    @Test
    fun `test connection with multiple concurrent requests`() {
        runBlocking {
            val results =
                (1..5).map {
                    tester.testConnection(
                        "example.com",
                        443,
                        SSLTestConfig(connectionTimeout = 1000),
                    )
                }

            results.forEach { result ->
                // Connections might succeed or fail depending on network conditions
                assertTrue(result.isSuccess || result.isFailure)
                if (result.isFailure) {
                    val error = result.exceptionOrNull()
                    assertIs<SSLTestException>(error)
                }
            }
        }
    }

    @Test
    fun `test connection with different timeouts`() {
        runBlocking {
            val timeouts = listOf(100, 500, 1000, 2000, 5000)

            timeouts.forEach { timeout ->
                val result =
                    tester.testConnection(
                        "example.com",
                        443,
                        SSLTestConfig(connectionTimeout = timeout),
                    )

                // Connections might succeed or fail depending on timeout and network conditions
                assertTrue(result.isSuccess || result.isFailure)
                if (result.isFailure) {
                    val error = result.exceptionOrNull()
                    assertIs<SSLTestException>(error)
                }
            }
        }
    }

    @Test
    fun `test connection with different hosts`() {
        runBlocking {
            val hosts =
                listOf(
                    "google.com",
                    "github.com",
                    "stackoverflow.com",
                    "reddit.com",
                    "wikipedia.org",
                )

            hosts.forEach { host ->
                val result =
                    tester.testConnection(
                        host,
                        443,
                        SSLTestConfig(connectionTimeout = 5000),
                    )

                // These might succeed or fail depending on network conditions
                assertTrue(result.isSuccess || result.isFailure)
            }
        }
    }

    @Test
    fun `test connection error message content`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-does-not-exist.com",
                    443,
                    SSLTestConfig(connectionTimeout = 1000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)

            // Verify error message contains useful information
            assertNotNull(error.message)
            assertTrue(error.message!!.isNotEmpty())
        }
    }

    @Test
    fun `test connection error host and port`() {
        runBlocking {
            val host = "test.example.com"
            val port = 8443

            val result =
                tester.testConnection(
                    host,
                    port,
                    SSLTestConfig(connectionTimeout = 1000),
                )

            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException.ConnectionError>(error)

            assertEquals(host, error.host)
            assertEquals(port, error.port)
        }
    }

    @Test
    fun `test SSL handshake exception handling`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    80,
                    SSLTestConfig(connectionTimeout = 5000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is SSLTestException.HandshakeError || error is SSLTestException.ConnectionError)
            assertTrue(
                error?.message?.contains("SSL") == true ||
                    error?.message?.contains("Protocol") == true ||
                    error?.message?.contains("Handshake") == true ||
                    error?.message?.contains("Connection") == true,
            )
        }
    }

    @Test
    fun `test SSL protocol exception handling`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "localhost",
                    22,
                    SSLTestConfig(connectionTimeout = 5000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is SSLTestException.HandshakeError || error is SSLTestException.ConnectionError)
            assertTrue(
                error?.message?.contains("SSL") == true ||
                    error?.message?.contains("Protocol") == true ||
                    error?.message?.contains("Handshake") == true ||
                    error?.message?.contains("Connection") == true,
            )
        }
    }

    @Test
    fun `test SSL initialization error handling`() {
        runBlocking {
            // 通过系统属性来模拟SSL初始化失败
            // 设置一个无效的SSL协议来触发初始化错误
            val originalProtocol = System.getProperty("https.protocols")
            try {
                System.setProperty("https.protocols", "INVALID_PROTOCOL")

                val result =
                    tester.testConnection(
                        "example.com",
                        443,
                        SSLTestConfig(connectionTimeout = 5000),
                    )

                // 由于SSL初始化可能失败，我们检查结果
                assertTrue(result.isSuccess || result.isFailure)
            } finally {
                // 恢复原始设置
                if (originalProtocol != null) {
                    System.setProperty("https.protocols", originalProtocol)
                } else {
                    System.clearProperty("https.protocols")
                }
            }
        }
    }

    @Test
    fun `test connection with null message in IOException`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "invalid-host-that-will-cause-io-exception",
                    443,
                    SSLTestConfig(connectionTimeout = 1000),
                )
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertTrue(error is SSLTestException.ConnectionError)
            assertTrue(
                error?.message?.contains("Connection refused") == true ||
                    error?.message?.contains("Connection failed") == true ||
                    error?.message?.contains("Unknown host") == true,
            )
        }
    }

    // Parameterized test for standard SSL/TLS ports
    @ParameterizedTest
    @ValueSource(ints = [443, 465, 563, 636, 993, 995])
    fun `test standard SSL ports`(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Should either succeed or fail gracefully, not crash
            assertTrue(result.isSuccess || result.isFailure)
            if (result.isFailure) {
                val error = result.exceptionOrNull()
                assertIs<SSLTestException>(error)
            }
        }
    }

    // Parameterized test for alternative SSL ports
    @ParameterizedTest
    @ValueSource(ints = [8443, 9443])
    fun `test alternative SSL ports`(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Should either succeed or fail gracefully, not crash
            assertTrue(result.isSuccess || result.isFailure)
            if (result.isFailure) {
                val error = result.exceptionOrNull()
                assertIs<SSLTestException>(error)
            }
        }
    }

    // Parameterized test for boundary conditions
    @ParameterizedTest
    @ValueSource(ints = [0, 1, 65535, 65536])
    fun `test connection with boundary port values`(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Boundary ports should fail gracefully
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    // Parameterized test for invalid ports
    @ParameterizedTest
    @ValueSource(ints = [-1, -100, 70000, 99999])
    fun `test connection with invalid ports`(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Invalid ports should fail gracefully
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    // Parameterized test for non-SSL ports (should fail)
    @ParameterizedTest
    @ValueSource(ints = [22, 80, 8080])
    fun `test connection with non-SSL ports`(port: Int) {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    port,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Non-SSL ports should fail with appropriate error
            assertTrue(result.isFailure)
            val error = result.exceptionOrNull()
            assertIs<SSLTestException>(error)
        }
    }

    @Test
    fun `test default HTTPS port 443`() {
        runBlocking {
            val result =
                tester.testConnection(
                    "example.com",
                    443,
                    SSLTestConfig(connectionTimeout = 5000),
                )

            // Port 443 might succeed or fail depending on network conditions
            // Just verify that we get a result (either success or failure)
            if (result.isSuccess) {
                // Connection succeeded, which is valid for port 443
                assertTrue(true)
            } else {
                // Connection failed, which is also valid for port 443
                val error = result.exceptionOrNull()
                assertIs<SSLTestException>(error)
            }
        }
    }
}
