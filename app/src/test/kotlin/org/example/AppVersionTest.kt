package org.example

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AppVersionTest {
    @Test
    fun `test version constants`() {
        assertEquals("0.0.2", AppVersion.VERSION)
        assertEquals("ssl-test", AppVersion.NAME)
        assertEquals("SSL/TLS Connection Test Tool", AppVersion.DESCRIPTION)
    }

    @Test
    fun `test version format`() {
        val version = AppVersion.VERSION
        assertTrue(version.matches(Regex("\\d+\\.\\d+\\.\\d+")))
    }

    @Test
    fun `test name constant`() {
        val name = AppVersion.NAME
        assertEquals("ssl-test", name)
    }

    @Test
    fun `test description constant`() {
        val description = AppVersion.DESCRIPTION
        assertEquals("SSL/TLS Connection Test Tool", description)
    }
}
