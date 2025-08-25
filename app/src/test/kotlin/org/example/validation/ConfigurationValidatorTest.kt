package org.example.validation

import org.example.SSLConstants
import org.example.exception.SSLTestException
import org.example.model.OutputFormat
import org.example.model.SSLTestConfig
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConfigurationValidatorTest {
    private val validator = ConfigurationValidator()

    @Test
    fun `test valid configuration should pass validation`() {
        val config =
            SSLTestConfig(
                connectionTimeout = 5000,
                readTimeout = 5000,
                handshakeTimeout = 10000,
                format = OutputFormat.JSON,
                outputFile = "test.json",
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Success)
    }

    @Test
    fun `test connection timeout below minimum should fail validation`() {
        val config =
            SSLTestConfig(
                connectionTimeout = SSLConstants.MIN_TIMEOUT - 1,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        assertEquals(1, failure.errors.size)

        val error = failure.errors.first()
        assertEquals("connectionTimeout", error.field)
        assertTrue(error.message.contains("must be at least"))
    }

    @Test
    fun `test connection timeout above maximum should fail validation`() {
        val config =
            SSLTestConfig(
                connectionTimeout = SSLConstants.MAX_TIMEOUT + 1,
                readTimeout = SSLConstants.DEFAULT_TIMEOUT,
                handshakeTimeout = SSLConstants.DEFAULT_HANDSHAKE_TIMEOUT,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        assertEquals(1, failure.errors.size)

        val error = failure.errors.first()
        assertEquals("connectionTimeout", error.field)
        assertTrue(error.message.contains("cannot exceed"))
    }

    @Test
    fun `test read timeout validation`() {
        val config =
            SSLTestConfig(
                readTimeout = SSLConstants.MIN_TIMEOUT - 1,
                connectionTimeout = SSLConstants.DEFAULT_TIMEOUT,
                handshakeTimeout = SSLConstants.DEFAULT_HANDSHAKE_TIMEOUT,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("readTimeout", error.field)
    }

    @Test
    fun `test handshake timeout validation`() {
        val config =
            SSLTestConfig(
                handshakeTimeout = SSLConstants.MIN_HANDSHAKE_TIMEOUT - 1,
                connectionTimeout = SSLConstants.DEFAULT_TIMEOUT,
                readTimeout = SSLConstants.DEFAULT_TIMEOUT,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("handshakeTimeout", error.field)
    }

    @Test
    fun `test max retries validation`() {
        val config =
            SSLTestConfig(
                maxRetries = -1,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("maxRetries", error.field)
        assertTrue(error.message.contains("cannot be negative"))
    }

    @Test
    fun `test max retries above limit should fail validation`() {
        val config =
            SSLTestConfig(
                maxRetries = SSLConstants.MAX_RETRIES + 1,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("maxRetries", error.field)
        assertTrue(error.message.contains("cannot exceed"))
    }

    @Test
    fun `test retry delay validation`() {
        val config =
            SSLTestConfig(
                retryDelay = -1L,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("retryDelay", error.field)
        assertTrue(error.message.contains("cannot be negative"))
    }

    @Test
    fun `test retry delay above limit should fail validation`() {
        val config =
            SSLTestConfig(
                retryDelay = SSLConstants.MAX_RETRY_DELAY + 1,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("retryDelay", error.field)
        assertTrue(error.message.contains("cannot exceed"))
    }

    @Test
    fun `test output file path validation`() {
        val config =
            SSLTestConfig(
                outputFile = "",
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("outputFile", error.field)
        assertTrue(error.message.contains("cannot be blank"))
    }

    @Test
    fun `test output file path with invalid characters should fail validation`() {
        val config =
            SSLTestConfig(
                outputFile = "test/../file.txt",
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("outputFile", error.field)
        assertTrue(error.message.contains("invalid characters"))
    }

    @Test
    fun `test output file extension mismatch should fail validation`() {
        val config =
            SSLTestConfig(
                format = OutputFormat.JSON,
                outputFile = "test.txt",
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("outputFile", error.field)
        assertTrue(error.message.contains("extension should match"))
    }

    @Test
    fun `test configuration consistency validation`() {
        val config =
            SSLTestConfig(
                connectionTimeout = 5000,
                // Less than connection timeout
                handshakeTimeout = 3000,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        val error = failure.errors.first()
        assertEquals("handshakeTimeout", error.field)
        assertTrue(error.message.contains("should be greater than or equal to"))
    }

    @Test
    fun `test multiple validation errors`() {
        val config =
            SSLTestConfig(
                connectionTimeout = -1,
                readTimeout = -1,
                maxRetries = -1,
            )

        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Failure)

        val failure = result as ConfigurationValidator.ValidationResult.Failure
        assertTrue(failure.errors.size > 1)

        val errorFields = failure.errors.map { it.field }.toSet()
        assertTrue(errorFields.contains("connectionTimeout"))
        assertTrue(errorFields.contains("readTimeout"))
        assertTrue(errorFields.contains("maxRetries"))
    }

    @Test
    fun `test validateOrThrow with valid configuration should not throw`() {
        val config =
            SSLTestConfig(
                connectionTimeout = 5000,
                readTimeout = 5000,
                handshakeTimeout = 10000,
            )

        // Should not throw
        ConfigurationValidator.validateOrThrow(config)
    }

    @Test
    fun `test validateOrThrow with invalid configuration should throw`() {
        val config =
            SSLTestConfig(
                connectionTimeout = -1,
            )

        val exception =
            assertThrows<SSLTestException.ConfigurationError> {
                ConfigurationValidator.validateOrThrow(config)
            }

        assertTrue(exception.message?.contains("Invalid SSL test configuration") == true)
        assertEquals("MULTIPLE", exception.configField)
    }

    @Test
    fun `test validation error to exception conversion`() {
        val error =
            ConfigurationValidator.ValidationError(
                field = "testField",
                message = "Test error message",
                expectedValue = "Expected value",
                actualValue = "Actual value",
            )

        val exception = error.toException()

        assertEquals("testField: Test error message", exception.message)
        assertEquals("testField", exception.configField)
        assertEquals("Expected value", exception.expectedValue)
        assertEquals("Actual value", exception.actualValue)
    }

    @Test
    fun `test default configuration should pass validation`() {
        val config = SSLTestConfig.default()
        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Success)
    }

    @Test
    fun `test quick test configuration should pass validation`() {
        val config = SSLTestConfig.quickTest()
        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Success)
    }

    @Test
    fun `test detailed test configuration should pass validation`() {
        val config = SSLTestConfig.detailedTest()
        val result = validator.validate(config)
        assertTrue(result is ConfigurationValidator.ValidationResult.Success)
    }
}
