package org.example.cli

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.factory.ComponentFactoryManager
import org.example.factory.TestComponentFactory
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat
import org.example.model.SSLConnection
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Duration
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class SSLTestCommandTest {
    private lateinit var mockSSLTester: SSLConnectionTester
    private lateinit var mockCertValidator: CertificateValidator
    private lateinit var mockFormatter: OutputFormatter
    private lateinit var testFactory: TestComponentFactory

    @BeforeEach
    fun setUp() {
        mockSSLTester = mockk<SSLConnectionTester>()
        mockCertValidator = mockk<CertificateValidator>()
        mockFormatter = mockk<OutputFormatter>()

        // 设置模拟格式化器的行为
        every { mockFormatter.format(any()) } returns "Mocked output"
        every { mockFormatter.getFileExtension() } returns "txt"

        testFactory =
            TestComponentFactory(
                sslConnectionTester = mockSSLTester,
                certificateValidator = mockCertValidator,
                formatters = mapOf(OutputFormat.TXT to mockFormatter),
            )

        ComponentFactoryManager.setFactory(testFactory)
    }

    @AfterEach
    fun tearDown() {
        ComponentFactoryManager.resetToDefault()
    }

    @Test
    fun `test command initialization with dependency injection`() {
        val command = SSLTestCommand()

        assertNotNull(command)
        assertEquals("ssl-test", command.javaClass.getAnnotation(picocli.CommandLine.Command::class.java).name)
    }

    @Test
    fun `test command with valid parameters`() =
        runBlocking {
            val command = SSLTestCommand()
            command.host = "example.com"
            command.port = 443
            command.connectionTimeout = 5000
            command.format = OutputFormat.TXT

            // 模拟成功的SSL连接
            val mockConnection =
                SSLConnection(
                    host = "example.com",
                    port = 443,
                    protocol = "TLSv1.3",
                    cipherSuite = "TLS_AES_256_GCM_SHA384",
                    handshakeTime = Duration.ofMillis(150),
                    isSecure = true,
                    certificateChain = emptyList(),
                )

            coEvery {
                mockSSLTester.testConnection(any(), any(), any())
            } returns Result.success(mockConnection)

            // 执行命令
            val exitCode = command.call()

            assertEquals(0, exitCode)

            // 验证SSL测试器被调用
            coVerify {
                mockSSLTester.testConnection("example.com", 443, any())
            }
        }

    @Test
    fun `test command with connection failure`() =
        runBlocking {
            val command = SSLTestCommand()
            command.host = "invalid-host.com"
            command.port = 443
            command.format = OutputFormat.TXT

            // 模拟连接失败
            coEvery {
                mockSSLTester.testConnection(any(), any(), any())
            } returns Result.failure(Exception("Connection failed"))

            // 执行命令
            val exitCode = command.call()

            assertEquals(1, exitCode) // EXIT_CONNECTION_ERROR
        }

    @Test
    fun `test command with invalid timeout`() {
        val command = SSLTestCommand()
        command.host = "example.com"
        command.connectionTimeout = -1

        // 执行命令
        val exitCode = command.call()

        assertEquals(2, exitCode) // EXIT_INVALID_PARAMETERS
    }

    @Test
    fun `test command with different output formats`() =
        runBlocking {
            val formats = listOf(OutputFormat.TXT, OutputFormat.JSON, OutputFormat.YAML, OutputFormat.EMOJI)
            val allFormatters =
                formats.associateWith {
                    mockk<OutputFormatter> {
                        every { format(any()) } returns "Mocked output"
                        every { getFileExtension() } returns "txt"
                    }
                }
            val testFactory =
                TestComponentFactory(
                    sslConnectionTester = mockSSLTester,
                    certificateValidator = mockCertValidator,
                    formatters = allFormatters,
                )
            ComponentFactoryManager.setFactory(testFactory)

            formats.forEach { format ->
                val command = SSLTestCommand()
                command.host = "example.com"
                command.format = format

                // 模拟成功的SSL连接
                val mockConnection =
                    SSLConnection(
                        host = "example.com",
                        port = 443,
                        protocol = "TLSv1.3",
                        cipherSuite = "TLS_AES_256_GCM_SHA384",
                        handshakeTime = Duration.ofMillis(150),
                        isSecure = true,
                        certificateChain = emptyList(),
                    )

                coEvery {
                    mockSSLTester.testConnection(any(), any(), any())
                } returns Result.success(mockConnection)

                // 执行命令
                val exitCode = command.call()

                assertEquals(0, exitCode)
            }
        }

    @Test
    fun `test command parameter validation`() {
        val command = SSLTestCommand()

        // 测试默认值
        assertEquals(443, command.port)
        assertEquals(5000, command.connectionTimeout)
        assertEquals(OutputFormat.TXT, command.format)

        // 测试参数设置
        command.host = "test.example.com"
        command.port = 8443
        command.connectionTimeout = 10000
        command.format = OutputFormat.JSON
        command.outputFile = "test.json"

        assertEquals("test.example.com", command.host)
        assertEquals(8443, command.port)
        assertEquals(10000, command.connectionTimeout)
        assertEquals(OutputFormat.JSON, command.format)
        assertEquals("test.json", command.outputFile)
    }
}
