package org.example.cli

import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import org.example.model.OutputFormat
import org.example.model.SSLConnection
import org.example.model.SSLTestConfig
import org.example.output.OutputFormatter
import org.example.service.SSLConnectionTester
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import org.koin.core.qualifier.named
import picocli.CommandLine.Command
import picocli.CommandLine.ITypeConverter
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.io.File
import java.time.Duration
import java.util.concurrent.Callable

private val logger = KotlinLogging.logger {}

class OutputFormatConverter : ITypeConverter<OutputFormat> {
    override fun convert(value: String): OutputFormat = OutputFormat.valueOf(value)
}

@Command(
    name = "ssl-test",
    description = ["Test SSL/TLS connections to remote hosts"],
    mixinStandardHelpOptions = true,
    version = ["0.0.1"],
)
class SSLTestCommand : Callable<Int>, KoinComponent {
    private val sslTester: SSLConnectionTester by inject()

    @Parameters(
        index = "0",
        description = ["The host to test the SSL/TLS connection with"],
    )
    lateinit var host: String

    @Option(
        names = ["-p", "--port"],
        description = ["Port number (default: \${DEFAULT-VALUE})"],
    )
    var port: Int = 443

    @Option(
        names = ["--connect-timeout"],
        description = ["Connection timeout in milliseconds (default: \${DEFAULT-VALUE})"],
    )
    var connectionTimeout: Int = 5000

    @Option(
        names = ["-f", "--format"],
        description = ["Output format (txt, json, yaml) (default: \${DEFAULT-VALUE})"],
        converter = [OutputFormatConverter::class],
    )
    var format: OutputFormat = OutputFormat.TXT

    @Option(
        names = ["-o", "--output"],
        description = ["Output file path"],
    )
    var outputFile: String? = null

    override fun call(): Int =
        runBlocking {
            try {
                logger.info { "Testing SSL connection to $host:$port" }

                val config =
                    SSLTestConfig(
                        connectionTimeout = connectionTimeout,
                        format = format,
                        outputFile = outputFile,
                    )

                sslTester.testConnection(host, port, config)
                    .onSuccess { connection ->
                        val formatter: OutputFormatter by inject(named(format.value.lowercase()))
                        val output = formatter.format(connection)

                        if (outputFile != null) {
                            File(outputFile!!).writeText(output)
                            logger.info { "Results written to $outputFile" }
                        } else {
                            println(output)
                        }
                    }
                    .onFailure { error ->
                        val failedConnection =
                            SSLConnection(
                                host = host,
                                port = port,
                                protocol = "Error: ${error.message}",
                                cipherSuite = "Unknown",
                                handshakeTime = Duration.ofMillis(0),
                                isSecure = false,
                                certificateChain = emptyList(),
                            )

                        val formatter: OutputFormatter by inject(named("txt"))
                        System.err.println(formatter.format(failedConnection))
                        return@runBlocking 1
                    }

                0
            } catch (e: Exception) {
                logger.error(e) { "Command execution failed" }
                1
            }
        }
}
