package org.example.cli

import org.example.model.OutputFormat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import picocli.CommandLine
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SSLTestCommandTest {
    private lateinit var command: SSLTestCommand
    private lateinit var originalOut: PrintStream
    private lateinit var originalErr: PrintStream
    private lateinit var outContent: ByteArrayOutputStream
    private lateinit var errContent: ByteArrayOutputStream

    @BeforeEach
    fun setUp() {
        command = SSLTestCommand()
        originalOut = System.out
        originalErr = System.err
        outContent = ByteArrayOutputStream()
        errContent = ByteArrayOutputStream()
        System.setOut(PrintStream(outContent))
        System.setErr(PrintStream(errContent))
    }

    @AfterEach
    fun tearDown() {
        System.setOut(originalOut)
        System.setErr(originalErr)
    }

    @Test
    fun `test command initialization with default values`() {
        assertEquals(443, command.port)
        assertEquals(5000, command.connectionTimeout)
        assertEquals(OutputFormat.TXT, command.format)
        assertNull(command.outputFile)
    }

    @Test
    fun `test command parameter setting`() {
        command.host = "test.example.com"
        command.port = 8443
        command.connectionTimeout = 3000
        command.format = OutputFormat.JSON
        command.outputFile = "test.json"

        assertEquals("test.example.com", command.host)
        assertEquals(8443, command.port)
        assertEquals(3000, command.connectionTimeout)
        assertEquals(OutputFormat.JSON, command.format)
        assertEquals("test.json", command.outputFile)
    }

    @Test
    fun `test command with valid host`() {
        command.host = "example.com"

        val exitCode = command.call()

        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with invalid host`() {
        command.host = "invalid-host-that-does-not-exist.com"

        val exitCode = command.call()

        assertEquals(1, exitCode)
    }

    @Test
    fun `test command with custom timeout`() {
        command.host = "example.com"
        command.connectionTimeout = 1000 // 1 second timeout

        val exitCode = command.call()

        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with custom port`() {
        command.host = "example.com"
        command.port = 8443

        val exitCode = command.call()

        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command line parsing edge cases`() {
        // Test with empty string host
        val args1 = arrayOf("")
        CommandLine(command).parseArgs(*args1)
        assertEquals("", command.host)

        // Test with very long hostname
        val longHost = "a".repeat(1000) + ".example.com"
        val args2 = arrayOf(longHost)
        CommandLine(command).parseArgs(*args2)
        assertEquals(longHost, command.host)
    }

    @Test
    fun `test command line parsing with special characters`() {
        val args = arrayOf("test-host.example.com")
        CommandLine(command).parseArgs(*args)

        assertEquals("test-host.example.com", command.host)
    }

    @Test
    fun `test command line parsing with IPv4 address`() {
        val args = arrayOf("192.168.1.1")
        CommandLine(command).parseArgs(*args)

        assertEquals("192.168.1.1", command.host)
    }

    @Test
    fun `test command line parsing with IPv6 address`() {
        val args = arrayOf("::1")
        CommandLine(command).parseArgs(*args)

        assertEquals("::1", command.host)
    }

    @Test
    fun `test command with port parameter`() {
        val args = arrayOf("example.com", "--port", "8443")
        CommandLine(command).parseArgs(*args)

        assertEquals("example.com", command.host)
        assertEquals(8443, command.port)
    }

    @Test
    fun `test command with short port option`() {
        val args = arrayOf("example.com", "-p", "9443")
        CommandLine(command).parseArgs(*args)

        assertEquals("example.com", command.host)
        assertEquals(9443, command.port)
    }

    @Test
    fun `test command with negative timeout`() {
        val args = arrayOf("example.com", "--connect-timeout", "-1")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(2, exitCode) // picocli validation error
    }

    @Test
    fun `test command with zero timeout`() {
        val args = arrayOf("example.com", "--connect-timeout", "0")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail, not validation error
    }

    @Test
    fun `test command with very large timeout`() {
        val args = arrayOf("example.com", "--connect-timeout", "999999")
        val exitCode = CommandLine(command).execute(*args)

        // Exit code depends on network connectivity: 0 for success, 1 for connection failure
        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with empty hostname`() {
        val args = arrayOf("")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with whitespace only hostname`() {
        val args = arrayOf("   ")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with special characters in hostname`() {
        val args = arrayOf("test-host.example.com")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with IPv4 address`() {
        val args = arrayOf("192.168.1.1")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with IPv6 address`() {
        val args = arrayOf("::1")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with all options`() {
        val args =
            arrayOf(
                "example.com",
                "--port", "8443",
                "--connect-timeout", "10000",
                "--format", "json",
                "--output", "test_output.json",
            )
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with short options`() {
        val args =
            arrayOf(
                "example.com",
                "-p", "9443",
                "-f",
                "yaml",
                "-o",
                "test_output.yaml",
            )
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(1, exitCode) // Connection will fail
    }

    @Test
    fun `test command with mixed case format`() {
        val args = arrayOf("example.com", "--format", "Json")
        val exitCode = CommandLine(command).execute(*args)

        // Exit code depends on network connectivity: 0 for success, 1 for connection failure
        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with uppercase format`() {
        val args = arrayOf("example.com", "--format", "JSON")
        val exitCode = CommandLine(command).execute(*args)

        // Exit code depends on network connectivity: 0 for success, 1 for connection failure
        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with maximum valid timeout`() {
        val args = arrayOf("example.com", "--connect-timeout", "30000")
        val exitCode = CommandLine(command).execute(*args)

        // Exit code depends on network connectivity: 0 for success, 1 for connection failure
        assertTrue(exitCode in listOf(0, 1))
    }

    @Test
    fun `test command with timeout above maximum`() {
        val args = arrayOf("example.com", "--connect-timeout", "2147483648")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(2, exitCode) // picocli validation error
    }

    @Test
    fun `test command with timeout below minimum`() {
        val args = arrayOf("example.com", "--connect-timeout", "-1")
        val exitCode = CommandLine(command).execute(*args)

        assertEquals(2, exitCode) // picocli validation error
    }
}
