package org.example

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AppVersionTest {
    @Test
    fun `test version constants and format`() {
        // Test all constants
        assertEquals("0.0.2", AppVersion.VERSION)
        assertEquals("ssl-test", AppVersion.NAME)
        assertEquals("SSL/TLS Connection Test Tool", AppVersion.DESCRIPTION)

        // Test version format
        assertTrue(AppVersion.VERSION.matches(Regex("\\d+\\.\\d+\\.\\d+")))
    }
}
