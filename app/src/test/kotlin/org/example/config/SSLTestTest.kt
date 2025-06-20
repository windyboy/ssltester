package org.example.config

import org.example.createFormatter
import org.example.model.OutputFormat
import org.example.output.TextOutputFormatter
import org.example.parseConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SSLTestTest {
    @Test
    fun `test default config`() {
        val config = parseConfig(arrayOf("example.com"))
        val formatter = createFormatter(config.format)

        assertEquals(5000, config.connectionTimeout)
        assertEquals(OutputFormat.TXT, config.format)
        assertEquals(null, config.outputFile)
        assertIs<TextOutputFormatter>(formatter)
    }

    @Test
    fun `test custom timeout`() {
        val config = parseConfig(arrayOf("example.com", "--connect-timeout", "10000"))

        assertEquals(10000, config.connectionTimeout)
        assertEquals(OutputFormat.TXT, config.format)
        assertEquals(null, config.outputFile)
    }

    @Test
    fun `test custom output format`() {
        val config = parseConfig(arrayOf("example.com", "--format", "JSON"))

        assertEquals(5000, config.connectionTimeout)
        assertEquals(OutputFormat.JSON, config.format)
        assertEquals(null, config.outputFile)
    }

    @Test
    fun `test output file`() {
        val config = parseConfig(arrayOf("example.com", "--output", "test.txt"))

        assertEquals(5000, config.connectionTimeout)
        assertEquals(OutputFormat.TXT, config.format)
        assertEquals("test.txt", config.outputFile)
    }

    @Test
    fun `test all options`() {
        val config =
            parseConfig(
                arrayOf(
                    "example.com",
                    "--connect-timeout",
                    "10000",
                    "--format",
                    "JSON",
                    "--output",
                    "test.json",
                ),
            )

        assertEquals(10000, config.connectionTimeout)
        assertEquals(OutputFormat.JSON, config.format)
        assertEquals("test.json", config.outputFile)
    }

    @Test
    fun `test formatter creation`() {
        val formatter = createFormatter(OutputFormat.TXT)
        assertIs<TextOutputFormatter>(formatter)
    }
}
