package org.example.di

import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter

/**
 * 服务定位器接口
 * 提供统一的依赖获取接口，支持依赖注入和测试
 */
interface ServiceLocator {
    /**
     * 获取 SSL 连接测试器
     */
    fun getSSLConnectionTester(): SSLConnectionTester

    /**
     * 获取证书验证器
     */
    fun getCertificateValidator(): CertificateValidator

    /**
     * 根据格式获取输出格式化器
     */
    fun getFormatter(format: org.example.model.OutputFormat): OutputFormatter

    /**
     * 获取所有支持的格式化器
     */
    fun getAllFormatters(): Map<org.example.model.OutputFormat, OutputFormatter>

    /**
     * 清理资源
     */
    fun shutdown()
}
