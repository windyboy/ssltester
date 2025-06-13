package org.example.domain.service

import org.example.domain.model.SSLConnection

/**
 * Interface for formatting SSL test results.
 */
interface OutputFormatter {
    /**
     * Formats the SSL test results.
     * @param connection The SSL connection test result
     * @return The formatted output as a string
     */
    fun format(connection: SSLConnection): String

    /**
     * Gets the file extension for this format.
     * @return The file extension (e.g., "json", "yaml", "txt")
     */
    fun getFileExtension(): String
} 