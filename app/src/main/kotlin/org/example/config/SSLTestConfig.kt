package org.example.config

import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.io.File

/**
 * Holds configuration parameters for the SSL/TLS test tool.
 * These parameters are populated by Picocli from command-line arguments.
 * Each field corresponds to a command-line option or positional parameter.
 */
class SSLTestConfig {
    @Parameters(index = "0", description = ["要测试的HTTPS URL"])
    var url: String = ""

    @Option(names = ["-t", "--timeout"], description = ["连接超时时间(毫秒)"])
    var connectionTimeout: Int = 5000

    @Option(names = ["-r", "--read-timeout"], description = ["读取超时时间(毫秒)"])
    var readTimeout: Int = 5000

    @Option(names = ["-f", "--follow-redirects"], description = ["是否跟随重定向"])
    var followRedirects: Boolean = false

    @Option(names = ["-k", "--keystore"], description = ["信任库文件路径"])
    var keystoreFile: File? = null

    @Option(names = ["-p", "--keystore-password"], description = ["信任库密码"], interactive = true)
    var keystorePassword: String? = null

    @Option(names = ["--client-cert"], description = ["客户端证书文件路径"])
    var clientCertFile: File? = null

    @Option(names = ["--client-key"], description = ["客户端私钥文件路径"])
    var clientKeyFile: File? = null

    @Option(names = ["--client-key-password"], description = ["客户端私钥密码"], interactive = true)
    var clientKeyPassword: String? = null

    @Option(names = ["--client-cert-format"], description = ["客户端证书格式: PEM, DER"], defaultValue = "PEM")
    var clientCertFormat: CertificateFormat = CertificateFormat.PEM

    @Option(names = ["-o", "--output"], description = ["输出文件路径"])
    var outputFile: File? = null

    @Option(names = ["--format"], description = ["输出格式: TEXT, JSON, YAML"], defaultValue = "TEXT")
    var format: OutputFormat = OutputFormat.TEXT

    @Option(names = ["-v", "--verbose"], description = ["显示详细输出"])
    var verbose: Boolean = false

    @Option(names = ["--log-cert-details"], description = ["在日志中显示证书详细信息"], defaultValue = "true")
    var logCertDetails: Boolean = true

    @Option(names = ["-c", "--config"], description = ["配置文件路径 (YAML/JSON)"])
    var configFile: File? = null

    @Option(names = ["--check-ocsp"], description = ["是否检查OCSP"], defaultValue = "true")
    var checkOCSP: Boolean = true

    @Option(names = ["--check-crl"], description = ["是否检查CRL"], defaultValue = "true")
    var checkCRL: Boolean = true

    enum class OutputFormat {
        /** Plain text format, human-readable. */
        TEXT,
        /** JSON format, machine-readable. */
        JSON,
        /** YAML format, human and machine-readable. */
        YAML
    }

    enum class CertificateFormat {
        PEM, DER
    }
} 