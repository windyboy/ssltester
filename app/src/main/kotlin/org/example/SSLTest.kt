package org.example

import org.example.cert.CertificateValidatorImpl
import org.example.cert.ClientCertificateManagerImpl
import org.example.config.SSLTestConfig
import org.example.exception.SSLTestException
import org.example.output.ResultFormatterImpl
import org.example.ssl.SSLConnectionTesterImpl
import org.slf4j.LoggerFactory

/**
 * Main class for SSL testing.
 */
class SSLTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val logger = LoggerFactory.getLogger(SSLTest::class.java)
            try {
                val config = SSLTestConfig.parseArgs(args)
                val test = SSLTest()
                test.runTest(config)
            } catch (e: SSLTestException) {
                logger.error("Test failed: ${e.message}")
                System.exit(1)
            } catch (e: Exception) {
                logger.error("Unexpected error: ${e.message}", e)
                System.exit(1)
            }
        }
    }

    /**
     * Runs the SSL test with the given configuration.
     * @param config The test configuration
     */
    fun runTest(config: SSLTestConfig) {
        val certificateValidator = CertificateValidatorImpl()
        val clientCertificateManager = ClientCertificateManagerImpl()
        val connectionTester = SSLConnectionTesterImpl(certificateValidator, clientCertificateManager)
        val resultFormatter = ResultFormatterImpl()

        val result = connectionTester.testConnection(config)
        resultFormatter.formatAndOutput(listOf(result), config)

        if (config.failOnError && !result.validationResult.chainValidationResult) {
            throw SSLTestException("SSL test failed: ${result.validationResult.message}")
        }
    }
}
