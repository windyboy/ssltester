package org.example.di

import io.mockk.mockk
import org.example.CertificateValidator
import org.example.SSLConnectionTester
import org.example.formatter.OutputFormatter
import org.example.model.OutputFormat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ServiceLocatorTest {
    @BeforeEach
    fun setUp() {
        ServiceLocatorProvider.resetToDefault()
    }

    @AfterEach
    fun tearDown() {
        ServiceLocatorProvider.shutdown()
    }

    @Test
    fun `test default service locator provides all dependencies`() {
        val locator = ServiceLocatorProvider.getServiceLocator()

        // 测试 SSL 连接测试器
        val sslTester = locator.getSSLConnectionTester()
        assertNotNull(sslTester)
        assertTrue(sslTester is org.example.DefaultSSLConnectionTester)

        // 测试证书验证器
        val certValidator = locator.getCertificateValidator()
        assertNotNull(certValidator)
        assertTrue(certValidator is CertificateValidator)

        // 测试所有格式化器
        val formatters = locator.getAllFormatters()
        assertEquals(4, formatters.size) // TXT, JSON, YAML, EMOJI

        assertTrue(formatters.containsKey(OutputFormat.TXT))
        assertTrue(formatters.containsKey(OutputFormat.JSON))
        assertTrue(formatters.containsKey(OutputFormat.YAML))
        assertTrue(formatters.containsKey(OutputFormat.EMOJI))
    }

    @Test
    fun `test service locator provides correct formatter for each format`() {
        val locator = ServiceLocatorProvider.getServiceLocator()

        // 测试 TXT 格式化器
        val txtFormatter = locator.getFormatter(OutputFormat.TXT)
        assertNotNull(txtFormatter)
        assertTrue(txtFormatter is org.example.formatter.TextOutputFormatter)
        assertEquals("txt", txtFormatter.getFileExtension())

        // 测试 JSON 格式化器
        val jsonFormatter = locator.getFormatter(OutputFormat.JSON)
        assertNotNull(jsonFormatter)
        assertTrue(jsonFormatter is org.example.formatter.JsonOutputFormatter)
        assertEquals("json", jsonFormatter.getFileExtension())

        // 测试 YAML 格式化器
        val yamlFormatter = locator.getFormatter(OutputFormat.YAML)
        assertNotNull(yamlFormatter)
        assertTrue(yamlFormatter is org.example.formatter.YamlOutputFormatter)
        assertEquals("yaml", yamlFormatter.getFileExtension())

        // 测试 EMOJI 格式化器
        val emojiFormatter = locator.getFormatter(OutputFormat.EMOJI)
        assertNotNull(emojiFormatter)
        assertTrue(emojiFormatter is org.example.formatter.EmojiTextOutputFormatter)
        assertEquals("txt", emojiFormatter.getFileExtension())
    }

    @Test
    fun `test service locator singleton behavior`() {
        val locator1 = ServiceLocatorProvider.getServiceLocator()
        val locator2 = ServiceLocatorProvider.getServiceLocator()

        // 应该返回同一个实例
        assertEquals(locator1, locator2)
    }

    @Test
    fun `test service locator caching behavior`() {
        val locator = ServiceLocatorProvider.getServiceLocator()

        // 第一次获取
        val formatter1 = locator.getFormatter(OutputFormat.TXT)
        val formatter2 = locator.getFormatter(OutputFormat.TXT)

        // 应该返回同一个实例（缓存）
        assertEquals(formatter1, formatter2)
    }

    @Test
    fun `test test service locator with mock dependencies`() {
        val mockSSLTester = mockk<SSLConnectionTester>()
        val mockCertValidator = mockk<CertificateValidator>()
        val mockFormatter = mockk<OutputFormatter>()

        val testFormatters: Map<org.example.model.OutputFormat, OutputFormatter> = mapOf(OutputFormat.TXT to mockFormatter)

        val testLocator =
            TestServiceLocator(
                sslConnectionTester = mockSSLTester,
                certificateValidator = mockCertValidator,
                formatters = testFormatters,
            )

        ServiceLocatorProvider.setServiceLocator(testLocator)

        val locator = ServiceLocatorProvider.getServiceLocator()
        assertEquals(mockSSLTester, locator.getSSLConnectionTester())
        assertEquals(mockCertValidator, locator.getCertificateValidator())
        assertEquals(mockFormatter, locator.getFormatter(OutputFormat.TXT))
    }

    @Test
    fun `test service locator shutdown`() {
        val locator = ServiceLocatorProvider.getServiceLocator()

        // 获取一些依赖
        locator.getSSLConnectionTester()
        locator.getCertificateValidator()
        locator.getFormatter(OutputFormat.TXT)

        // 关闭服务定位器
        locator.shutdown()

        // 验证可以重新获取（会创建新的实例）
        val newLocator = ServiceLocatorProvider.getServiceLocator()
        assertNotNull(newLocator.getSSLConnectionTester())
        assertNotNull(newLocator.getCertificateValidator())
        assertNotNull(newLocator.getFormatter(OutputFormat.TXT))
    }
}
