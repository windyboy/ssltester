package org.example.cli

import kotlinx.coroutines.runBlocking
import mu.KotlinLogging
import org.example.AppVersion
import org.example.SSLConnectionTester
import org.example.SSLConstants
import org.example.factory.ComponentFactoryManager
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
            throw IllegalArgumentException("Invalid format: $value. Supported formats: TXT, JSON, YAML, EMOJI.")
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
    version = [AppVersion.VERSION],
)
class SSLTestCommand : Callable<Int> {
    /** SSL 连接测试器实现 */
    private val sslTester: SSLConnectionTester = ComponentFactoryManager.getFactory().createSSLConnectionTester()

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
    var port: Int = SSLConstants.HTTPS_PORT

    /**
     * 连接超时时间（毫秒），默认 5000
     */
    @Option(
        names = ["--connect-timeout"],
        description = ["Connection timeout in milliseconds (default: 5000)"],
        paramLabel = "<connectionTimeout>",
        arity = "0..1",
    )
    var connectionTimeout: Int = SSLConstants.DEFAULT_TIMEOUT

    /**
     * 读取超时时间（毫秒），默认 5000
     */
    @Option(
        names = ["--read-timeout"],
        description = ["Read timeout in milliseconds (default: 5000)"],
        paramLabel = "<readTimeout>",
        arity = "0..1",
    )
    var readTimeout: Int = SSLConstants.DEFAULT_TIMEOUT

    /**
     * 握手超时时间（毫秒），默认 10000
     */
    @Option(
        names = ["--handshake-timeout"],
        description = ["SSL handshake timeout in milliseconds (default: 10000)"],
        paramLabel = "<handshakeTimeout>",
        arity = "0..1",
    )
    var handshakeTimeout: Int = SSLConstants.DEFAULT_HANDSHAKE_TIMEOUT

    /**
     * 输出格式，支持 TXT/JSON/YAML/EMOJI
     */
    @Option(
        names = ["-f", "--format"],
        description = ["Output format (txt, json, yaml, emoji) (default: TXT)"],
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
     * 是否启用主机名验证
     */
    @Option(
        names = ["--enable-hostname-verification"],
        description = ["Enable hostname verification (default: true)"],
        negatable = true,
    )
    var enableHostnameVerification: Boolean = true

    /**
     * 是否启用OCSP验证
     */
    @Option(
        names = ["--enable-ocsp-validation"],
        description = ["Enable OCSP validation (default: true)"],
        negatable = true,
    )
    var enableOCSPValidation: Boolean = true

    /**
     * 最大重试次数
     */
    @Option(
        names = ["--max-retries"],
        description = ["Maximum number of retries (default: 1)"],
        paramLabel = "<maxRetries>",
        arity = "0..1",
    )
    var maxRetries: Int = 1

    /**
     * 重试延迟（毫秒）
     */
    @Option(
        names = ["--retry-delay"],
        description = ["Delay between retries in milliseconds (default: 1000)"],
        paramLabel = "<retryDelay>",
        arity = "0..1",
    )
    var retryDelay: Long = 1000L

    /**
     * 命令执行主逻辑。
     * @return 退出码，0 表示成功，非 0 表示失败
     */
    override fun call(): Int =
        runBlocking {
            try {
                logger.info { "Testing SSL connection to $host:$port" }

                // Create configuration - validation happens automatically in SSLTestConfig constructor
                val config =
                    SSLTestConfig(
                        connectionTimeout = connectionTimeout,
                        readTimeout = readTimeout,
                        handshakeTimeout = handshakeTimeout,
                        format = format,
                        outputFile = outputFile,
                        enableHostnameVerification = enableHostnameVerification,
                        enableOCSPValidation = enableOCSPValidation,
                        maxRetries = maxRetries,
                        retryDelay = retryDelay,
                    )

                // Validate configuration
                config.validate()

                sslTester.testConnection(host, port, config)
                    .onSuccess { connection ->
                        val formatter = ComponentFactoryManager.getFactory().createFormatter(format)
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
                        val formatter = ComponentFactoryManager.getFactory().createFormatter(OutputFormat.TXT)
                        System.err.println(formatter.format(failedConnection))

                        // Return appropriate exit code based on error type
                        return@runBlocking when (error) {
                            is org.example.exception.SSLTestException.ConfigurationError ->
                                SSLConstants.EXIT_CONFIGURATION_ERROR
                            is org.example.exception.SSLTestException.CertificateError ->
                                SSLConstants.EXIT_CERTIFICATE_ERROR
                            else -> SSLConstants.EXIT_CONNECTION_ERROR
                        }
                    }

                SSLConstants.EXIT_SUCCESS
            } catch (e: Exception) {
                logger.error(e) { "Command execution failed" }

                // Return appropriate exit code based on exception type
                when (e) {
                    is org.example.exception.SSLTestException.ConfigurationError ->
                        SSLConstants.EXIT_CONFIGURATION_ERROR
                    is org.example.exception.SSLTestException.CertificateError ->
                        SSLConstants.EXIT_CERTIFICATE_ERROR
                    else -> SSLConstants.EXIT_CONNECTION_ERROR
                }
            }
        }
}
