package org.example.core

import org.example.domain.model.SSLConnection
import org.example.infrastructure.security.SSLConnectionTesterImpl
import org.example.config.SSLTestConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import kotlinx.coroutines.runBlocking
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.net.ConnectException
import kotlin.system.measureTimeMillis

class SSLConnectionTesterTest {
    private val tester = SSLConnectionTesterImpl()

    @Test
    fun `test successful connection to valid HTTPS site`() = runBlocking {
        val time = measureTimeMillis {
            val result = tester.testConnection("github.com", 443, SSLTestConfig(connectionTimeout = 200))
            
            assertTrue(result.isSecure)
            assertNotNull(result.protocol)
            assertNotNull(result.cipherSuite)
            assertTrue(result.certificateChain.isNotEmpty())
            assertEquals(443, result.port)
            assertEquals("github.com", result.host)
            // 验证协议版本
            assertTrue(result.protocol.startsWith("TLS"))
        }
        println("test successful connection to valid HTTPS site took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test connection with invalid host`() = runBlocking {
        val time = measureTimeMillis {
            val result = tester.testConnection("invalid-host-that-does-not-exist.com", 443, SSLTestConfig(connectionTimeout = 100))
            
            assertFalse(result.isSecure)
            assertTrue(result.certificateChain.isEmpty())
            assertTrue(result.protocol.startsWith("Unknown"))
            assertTrue(result.cipherSuite.isEmpty() || result.cipherSuite == "Unknown")
        }
        println("test connection with invalid host took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test connection with invalid port`() = runBlocking {
        val time = measureTimeMillis {
            // 使用更短的超时时间，避免长时间等待
            val result = tester.testConnection("github.com", 9999, SSLTestConfig(connectionTimeout = 50))
            
            assertFalse(result.isSecure)
            assertTrue(result.certificateChain.isEmpty())
            assertTrue(result.protocol.startsWith("Unknown"))
            assertTrue(result.cipherSuite.isEmpty() || result.cipherSuite == "Unknown")
        }
        println("test connection with invalid port took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test connection with timeout`() = runBlocking {
        val time = measureTimeMillis {
            // 使用更短的超时时间，避免长时间等待
            val config = SSLTestConfig(connectionTimeout = 10) // 10ms timeout
            val result = tester.testConnection("github.com", 443, config)
            
            assertFalse(result.isSecure)
            assertTrue(result.certificateChain.isEmpty())
            assertTrue(result.protocol.startsWith("Unknown"))
            assertTrue(result.cipherSuite.isEmpty() || result.cipherSuite == "Unknown")
        }
        println("test connection with timeout took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test connection to non-HTTPS port`() = runBlocking {
        val time = measureTimeMillis {
            val result = tester.testConnection("github.com", 80, SSLTestConfig(connectionTimeout = 100))
            
            assertFalse(result.isSecure)
            assertTrue(result.certificateChain.isEmpty())
            assertTrue(result.protocol.startsWith("Unknown"))
            assertTrue(result.cipherSuite.isEmpty() || result.cipherSuite == "Unknown")
        }
        println("test connection to non-HTTPS port took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }
} 