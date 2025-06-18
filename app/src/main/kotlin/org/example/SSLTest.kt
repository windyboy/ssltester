package org.example

import kotlinx.coroutines.runBlocking
import org.example.model.OutputFormat
import org.example.model.SSLConnection
import org.example.output.JsonOutputFormatter
import org.example.output.OutputFormatter
import org.example.output.TextOutputFormatter
import org.example.output.YamlOutputFormatter
import org.example.service.SSLConnectionTesterImpl
import java.io.File
import java.time.Duration

data class SSLTestConfig(
    val connectionTimeout: Int = 5000,
    val format: OutputFormat = OutputFormat.TXT,
    val outputFile: String? = null,
)

fun main(args: Array<String>) =
    runBlocking {
        if (args.isEmpty()) {
            println("Usage: ssl-test <host> [options]")
            println("Options:")
            println("  --port <port>              Port number (default: 443)")
            println("  --connect-timeout <ms>     Connection timeout in milliseconds (default: 5000)")
            println("  --output-format <format>   Output format (txt, json, yaml) (default: txt)")
            println("  --output-file <file>       Output file path (optional)")
            return@runBlocking
        }

        val host = args[0]
        val port = args.getOrNull(1)?.toIntOrNull() ?: 443
        val config = parseConfig(args.drop(2).toTypedArray())
        val tester = SSLConnectionTesterImpl()
        
        tester.testConnection(host, port, config)
            .onSuccess { connection ->
                val formatter = createFormatter(config.format)
                val output = formatter.format(connection)
                if (config.outputFile != null) {
                    File(config.outputFile).writeText(output)
                } else {
                    println(output)
                }
            }
            .onFailure { error ->
                val failedConnection = SSLConnection(
                    host = host,
                    port = port,
                    protocol = "Error: ${error.message}",
                    cipherSuite = "Unknown",
                    handshakeTime = Duration.ofMillis(0),
                    isSecure = false,
                    certificateChain = emptyList(),
                )
                val formatter = createFormatter(OutputFormat.TXT)
                println(formatter.format(failedConnection))
            }
    }

fun parseConfig(args: Array<String>): SSLTestConfig {
    var connectionTimeout = 5000
    var format: OutputFormat = OutputFormat.TXT
    var outputFile: String? = null
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--connect-timeout" -> connectionTimeout = args[++i].toInt()
            "--output-format" -> {
                format = when (args[++i].lowercase()) {
                    "txt" -> OutputFormat.TXT
                    "json" -> OutputFormat.JSON
                    "yaml" -> OutputFormat.YAML
                    else -> OutputFormat.UNKNOWN
                }
            }
            "--output-file" -> outputFile = args[++i]
        }
        i++
    }
    return SSLTestConfig(
        connectionTimeout = connectionTimeout,
        format = format,
        outputFile = outputFile,
    )
}

fun createFormatter(format: OutputFormat): OutputFormatter = when (format) {
    OutputFormat.TXT -> TextOutputFormatter()
    OutputFormat.JSON -> JsonOutputFormatter()
    OutputFormat.YAML -> YamlOutputFormatter()
    OutputFormat.UNKNOWN -> TextOutputFormatter()
}
