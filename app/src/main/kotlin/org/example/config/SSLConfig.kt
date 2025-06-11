package org.example.config

import org.example.model.SSLProtocol
import org.example.model.SSLVersion

data class SSLConfig(
    val host: String,
    val port: Int,
    val timeout: Int,
    val protocols: List<SSLProtocol>,
    val versions: List<SSLVersion>
) 