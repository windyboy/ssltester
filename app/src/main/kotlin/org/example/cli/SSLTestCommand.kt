package org.example.cli

import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import org.example.SSLConnectionTesterImpl
import org.example.Version
import org.example.formatter.JsonOutputFormatter
import org.example.formatter.TextOutputFormatter
import org.example.formatter.YamlOutputFormatter
import org.example.model.OutputFormat
import org.example.model.SSLConnection
import org.example.model.SSLTestConfig
import picocli.CommandLine.Command
import picocli.CommandLine.ITypeConverter
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.io.File
import java.time.Duration
import java.util.concurrent.Callable

private val logger = KotlinLogging.logger {}

class OutputFormatConverter : ITypeConverter<OutputFormat> {
    override fun convert(value: String): OutputFormat {
        val result = OutputFormat.valueOf(value.uppercase())
        if (result == OutputFormat.UNKNOWN) {
            throw IllegalArgumentException("Invalid format: $value. Supported formats: TXT, JSON, YAML.")
        }
        return result
    }
}

/**
 * SSL 测试命令行实现，负责参数解析和业务调度。
 */
@Command(
    name = "ssl-test",
    description = ["Test SSL/TLS connections to remote hosts"],
    mixinStandardHelpOptions = true,
    version = [Version.VERSION],
)
class SSLTestCommand : Callable<Int> {
    /** SSL 连接测试器实现 */
    private val sslTester = SSLConnectionTesterImpl()

    /**
     * 目标主机
     */
    @Parameters(
        index = "0",
        description = ["The host to test the SSL/TLS connection with"],
    )
    lateinit var host: String

    /**
     * 端口号，默认 443
     */
    @Option(
        names = ["-p", "--port"],
        description = ["Port number (default: 443)"],
        paramLabel = "<port>",
        arity = "0..1",
    )
    var port: Int = 443

    /**
     * 连接超时时间（毫秒），默认 5000
     */
    @Option(
        names = ["--connect-timeout"],
        description = ["Connection timeout in milliseconds (default: 5000)"],
        paramLabel = "<connectionTimeout>",
        arity = "0..1",
    )
    var connectionTimeout: Int = 5000

    /**
     * 输出格式，支持 TXT/JSON/YAML
     */
    @Option(
        names = ["-f", "--format"],
        description = ["Output format (txt, json, yaml) (default: TXT)"],
        converter = [OutputFormatConverter::class],
    )
    var format: OutputFormat = OutputFormat.TXT

    /**
     * 输出文件路径（可选）
     */
    @Option(
        names = ["-o", "--output"],
        description = ["Output file path"],
    )
    var outputFile: String? = null

    /**
     * 命令执行主逻辑。
     * @return 退出码，0 表示成功，非 0 表示失败
     */
    override fun call(): Int =
        runBlocking {
            // Manual validation for port and timeout
            if (port !in 1..65535) {
                System.err.println("Error: Port must be between 1 and 65535, but was $port")
                return@runBlocking 2
            }
            if (connectionTimeout < 0) {
                System.err.println("Error: Timeout cannot be negative, but was $connectionTimeout")
                return@runBlocking 2
            }
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
                        val output =
                            when (format) {
                                OutputFormat.TXT -> TextOutputFormatter().format(connection)
                                OutputFormat.JSON -> JsonOutputFormatter().format(connection)
                                OutputFormat.YAML -> YamlOutputFormatter().format(connection)
                                OutputFormat.UNKNOWN -> TextOutputFormatter().format(connection)
                            }

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
                        val formatter = TextOutputFormatter()
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
