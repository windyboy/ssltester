package org.example

import mu.KotlinLogging
import org.example.cli.SSLTestCommand
import org.example.config.appModule
import org.example.model.OutputFormat
import org.example.model.SSLTestConfig
import org.example.output.JsonOutputFormatter
import org.example.output.OutputFormatter
import org.example.output.TextOutputFormatter
import org.example.output.YamlOutputFormatter
import org.koin.core.context.startKoin
import picocli.CommandLine
import kotlin.system.exitProcess

private val logger = KotlinLogging.logger {}

fun main(args: Array<String>) {
    try {
        // Initialize Koin
        val koin =
            startKoin {
                printLogger()
                modules(appModule)
            }.koin

        // Get command instance from Koin
        val command = koin.get<SSLTestCommand>()

        // Execute command
        val exitCode = CommandLine(command).execute(*args)
        exitProcess(exitCode)
    } catch (e: Exception) {
        logger.error(e) { "Application failed to start" }
        exitProcess(1)
    }
}

/**
 * Parse command line arguments into SSLTestConfig
 */
fun parseConfig(args: Array<String>): SSLTestConfig {
    val command = SSLTestCommand()
    try {
        CommandLine(command).parseArgs(*args)
    } catch (e: Exception) {
        // Ignore parsing errors for testing - use defaults
    }

    return SSLTestConfig(
        connectionTimeout = command.connectionTimeout,
        format = command.format,
        outputFile = command.outputFile,
    )
}

/**
 * Create formatter based on output format
 */
fun createFormatter(format: OutputFormat): OutputFormatter {
    // Create a simple formatter without Koin for testing
    return when (format) {
        OutputFormat.TXT -> TextOutputFormatter()
        OutputFormat.JSON -> JsonOutputFormatter()
        OutputFormat.YAML -> YamlOutputFormatter()
        OutputFormat.UNKNOWN -> TextOutputFormatter()
    }
}
