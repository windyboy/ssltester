package org.example.config

import org.example.domain.model.OutputFormat

data class SSLTestConfig(
    val connectionTimeout: Int = 5000,
    val format: OutputFormat = OutputFormat.TXT,
    val outputFile: String? = null
) 