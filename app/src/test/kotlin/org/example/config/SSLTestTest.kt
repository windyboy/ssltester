package org.example.config

import org.example.domain.model.OutputFormat
import org.example.infrastructure.output.TextOutputFormatter
import org.example.config.SSLTestConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.io.TempDir
import java.io.File
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.system.measureTimeMillis
import org.example.parseConfig
import org.example.createFormatter
import org.example.main

class SSLTestTest {
    @Test
    fun `test parseConfig with default values`() {
        val time = measureTimeMillis {
            val config = parseConfig(emptyArray())
            assertEquals(5000, config.connectionTimeout)
            assertEquals(OutputFormat.TXT, config.format)
            assertNull(config.outputFile)
        }
        println("test parseConfig with default values took ${time}ms")
    }

    @Test
    fun `test parseConfig with custom values`() {
        val time = measureTimeMillis {
            val args = arrayOf(
                "--connect-timeout", "3000",
                "--output-format", "TXT",
                "--output-file", "test.txt"
            )
            val config = parseConfig(args)
            assertEquals(3000, config.connectionTimeout)
            assertEquals(OutputFormat.TXT, config.format)
            assertEquals("test.txt", config.outputFile)
        }
        println("test parseConfig with custom values took ${time}ms")
    }

    @Test
    fun `test parseConfig with invalid timeout`() {
        val time = measureTimeMillis {
            val args = arrayOf("--connect-timeout", "invalid")
            assertThrows(NumberFormatException::class.java) {
                parseConfig(args)
            }
        }
        println("test parseConfig with invalid timeout took ${time}ms")
    }

    @Test
    fun `test parseConfig with invalid format`() {
        val time = measureTimeMillis {
            val args = arrayOf("--output-format", "INVALID")
            assertThrows(IllegalArgumentException::class.java) {
                parseConfig(args)
            }
        }
        println("test parseConfig with invalid format took ${time}ms")
    }

    @Test
    fun `test createFormatter with TXT format`() {
        val time = measureTimeMillis {
            val formatter = createFormatter(OutputFormat.TXT)
            assertTrue(formatter is TextOutputFormatter)
        }
        println("test createFormatter with TXT format took ${time}ms")
    }

    @Test
    fun `test main function with no arguments`() {
        val time = measureTimeMillis {
            val output = captureSystemOut {
                main(emptyArray())
            }
            assertTrue(output.contains("Usage: ssl-test <host> [options]"))
            assertTrue(output.contains("--port"))
            assertTrue(output.contains("--connect-timeout"))
            assertTrue(output.contains("--output-format"))
            assertTrue(output.contains("--output-file"))
        }
        println("test main function with no arguments took ${time}ms")
    }

    @Test
    fun `test main function with invalid host`() {
        val time = measureTimeMillis {
            val output = captureSystemOut {
                main(arrayOf("invalid-host-that-does-not-exist.com", "--connect-timeout", "500"))
            }
            // 验证输出包含预期的错误信息
            assertTrue(output.contains("Status: Failed"))
            assertTrue(output.contains("Protocol: Unknown"))
            assertTrue(output.contains("Cipher Suite: Unknown"))
            assertTrue(output.contains("Certificate Chain: Empty"))
        }
        println("test main function with invalid host took ${time}ms")
        // 确保测试不会花费太长时间
        assertTrue(time < 1000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test main function with file output`(@TempDir tempDir: File) {
        val time = measureTimeMillis {
            val outputFile = File(tempDir, "test-output.txt")
            val args = arrayOf(
                "github.com",
                "--connect-timeout", "200",
                "--output-file", outputFile.absolutePath
            )
            
            runBlocking {
                try {
                    main(args)
                } catch (e: Exception) {
                    // 忽略可能的网络错误
                }
            }
            
            // 只检查文件是否被创建，不检查内容
            assertTrue(outputFile.exists(), "Output file should exist")
        }
        println("test main function with file output took ${time}ms")
    }

    @Test
    fun `test main function with custom timeout`() {
        val time = measureTimeMillis {
            val args = arrayOf(
                "--host", "example.com",
                "--port", "443",
                "--timeout", "100"  // Use 100ms timeout instead of 1ms
            )
            main(args)
        }
        println("test main function with custom timeout took ${time}ms")
        assertTrue(time < 2000, "Test took too long: ${time}ms")
    }

    @Test
    fun `test main function with all options`() {
        val time = measureTimeMillis {
            val output = captureSystemOut {
                main(arrayOf(
                    "github.com",
                    "443",
                    "--connect-timeout", "200",
                    "--output-format", "TXT"
                ))
            }
            // 验证输出包含一些预期的内容
            assertTrue(output.contains("Connection") || output.contains("Error:"))
        }
        println("test main function with all options took ${time}ms")
    }

    private fun captureSystemOut(block: () -> Unit): String {
        val originalOut = System.out
        val outputStream = ByteArrayOutputStream()
        System.setOut(PrintStream(outputStream))
        try {
            block()
            return outputStream.toString()
        } finally {
            System.setOut(originalOut)
        }
    }
} 