package org.example.config

import java.io.File
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import picocli.CommandLine

/**
 * Holds configuration parameters for the SSL/TLS test tool.
 * These parameters are populated by Picocli from command-line arguments.
 * Each field corresponds to a command-line option or positional parameter.
 */
class SSLTestConfig {
    @Parameters(index = "0", description = ["要测试的HTTPS URL"])
    var url: String = ""

    @Option(names = ["-k", "--keystore"], description = ["信任库文件路径"])
    var keystoreFile: File? = null

    @Option(names = ["-p", "--keystore-password"], description = ["信任库密码"])
    var keystorePassword: String? = null

    @Option(names = ["-c", "--client-cert"], description = ["客户端证书文件路径"])
    var clientCertFile: File? = null

    @Option(names = ["-i", "--client-key"], description = ["客户端私钥文件路径"])
    var clientKeyFile: File? = null

    @Option(names = ["-w", "--client-key-password"], description = ["客户端私钥密码"])
    var clientKeyPassword: String? = null

    @Option(names = ["-t", "--timeout"], description = ["连接超时时间(毫秒)"])
    var connectionTimeout: Int = 30000

    @Option(names = ["-r", "--read-timeout"], description = ["读取超时时间(毫秒)"])
    var readTimeout: Int = 30000

    @Option(names = ["-f", "--follow-redirects"], description = ["是否跟随重定向"])
    var followRedirects: Boolean = true

    @Option(names = ["--trust-all-hosts"], description = ["信任所有主机名"])
    var trustAllHosts: Boolean = false

    @Option(names = ["--format"], description = ["输出格式 (TEXT, JSON, YAML)"])
    var format: OutputFormat = OutputFormat.TEXT

    @Option(names = ["--config"], description = ["配置文件路径"])
    var configFile: File? = null

    @Option(names = ["-o", "--output"], description = ["输出文件路径"])
    var outputFile: File? = null

    @Option(names = ["--fail-on-error"], description = ["遇到错误时立即失败"])
    var failOnError: Boolean = true

    @Option(names = ["-v", "--verbose"], description = ["显示详细信息"])
    var verbose: Boolean = false

    enum class OutputFormat {
        /** Plain text format, human-readable. */
        TEXT,
        /** JSON format, machine-readable. */
        JSON,
        /** YAML format, human and machine-readable. */
        YAML
    }

    fun parseArgs(args: Array<String>) {
        val commandLine = CommandLine(this)
        commandLine.parseArgs(*args)
    }
} 