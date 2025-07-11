package org.example.factory

import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat

/**
 * 组件工厂接口
 * 负责创建应用中的各种组件实例
 */
interface ComponentFactory {
    /**
     * 创建 SSL 连接测试器
     */
    fun createSSLConnectionTester(): SSLConnectionTester

    /**
     * 创建证书验证器
     */
    fun createCertificateValidator(): CertificateValidator

    /**
     * 根据格式创建输出格式化器
     */
    fun createFormatter(format: OutputFormat): OutputFormatter

    /**
     * 创建所有支持的格式化器
     */
    fun createAllFormatters(): Map<OutputFormat, OutputFormatter>
}
