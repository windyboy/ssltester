package org.example.output

import org.example.config.SSLTestConfig
import org.example.model.SSLTestResult

/**
 * Interface for formatting SSL test results.
 */
interface ResultFormatter {
    /**
     * Formats and outputs the SSL test results.
     *
     * @param results The list of SSL test results to format and output
     * @param config The configuration for output formatting
     */
    fun formatAndOutput(results: List<SSLTestResult>, config: SSLTestConfig)

    /**
     * Formats the results as text.
     *
     * @param results The list of results to format
     * @return The formatted text
     */
    fun formatAsText(results: List<SSLTestResult>): String

    /**
     * Formats the results as JSON.
     *
     * @param results The list of results to format
     * @return The formatted JSON
     */
    fun formatAsJson(results: List<SSLTestResult>): String

    /**
     * Formats the results as YAML.
     *
     * @param results The list of results to format
     * @return The formatted YAML
     */
    fun formatAsYaml(results: List<SSLTestResult>): String
} 