package org.example

import kotlinx.coroutines.runBlocking
import org.example.domain.model.OutputFormat
import org.example.domain.model.SSLConnection
import org.example.domain.service.OutputFormatter
import org.example.config.SSLTestConfig
import org.example.infrastructure.output.TextOutputFormatter
import org.example.infrastructure.output.JsonOutputFormatter
import org.example.infrastructure.output.YamlOutputFormatter
import org.example.infrastructure.security.SSLConnectionTesterImpl
import java.io.File
import java.time.Duration

fun main(args: Array<String>) = runBlocking {
    if (args.isEmpty()) {
        println("Usage: ssl-test <host> [options]")
        println("Options:")
        println("  --port <port>              Port number (default: 443)")
        println("  --connect-timeout <ms>     Connection timeout in milliseconds (default: 5000)")
        println("  --output-format <format>   Output format (TXT) (default: TXT)")
        println("  --output-file <file>       Output file path (optional)")
        return@runBlocking
    }

    try {
        val host = args[0]
        val port = args.getOrNull(1)?.toIntOrNull() ?: 443
        val config = parseConfig(args.drop(2).toTypedArray())
        val tester = SSLConnectionTesterImpl()
        val connection = tester.testConnection(host, port, config)
        val formatter = createFormatter(config.format)
        val output = formatter.format(connection)
        if (config.outputFile != null) {
            File(config.outputFile).writeText(output)
        } else {
            println(output)
        }
    } catch (e: Exception) {
        val failedConnection = SSLConnection(
            host = args[0],
            port = args.getOrNull(1)?.toIntOrNull() ?: 443,
            protocol = "",
            cipherSuite = "",
            handshakeTime = Duration.ofMillis(0),
            isSecure = false,
            certificateChain = emptyList()
        )
        val formatter = createFormatter(OutputFormat.TXT)
        val output = formatter.format(failedConnection)
        println(output)
    }
}

fun parseConfig(args: Array<String>): SSLTestConfig {
    var connectionTimeout = 5000
    var format = OutputFormat.TXT
    var outputFile: String? = null
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--connect-timeout" -> connectionTimeout = args[++i].toInt()
            "--output-format" -> format = OutputFormat.valueOf(args[++i].uppercase())
            "--output-file" -> outputFile = args[++i]
        }
        i++
    }
    return SSLTestConfig(
        connectionTimeout = connectionTimeout,
        format = format,
        outputFile = outputFile
    )
}

fun createFormatter(format: OutputFormat): OutputFormatter {
    return when (format) {
        OutputFormat.TXT -> TextOutputFormatter()
        OutputFormat.JSON -> JsonOutputFormatter()
        OutputFormat.YAML -> YamlOutputFormatter()
        OutputFormat.UNKNOWN -> TextOutputFormatter()
    }
}
