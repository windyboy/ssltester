package org.example

import kotlin.test.*

class VersionTest {

    @Test
    fun `test version constants`() {
        assertEquals("0.0.2", Version.VERSION)
        assertEquals("ssl-test", Version.NAME)
        assertEquals("SSL/TLS Connection Test Tool", Version.DESCRIPTION)
    }

    @Test
    fun `test version format`() {
        val version = Version.VERSION
        assertTrue(version.matches(Regex("\\d+\\.\\d+\\.\\d+")))
    }

    @Test
    fun `test name format`() {
        val name = Version.NAME
        assertTrue(name.matches(Regex("[a-z-]+")))
    }

    @Test
    fun `test description content`() {
        val description = Version.DESCRIPTION
        assertTrue(description.contains("SSL"))
        assertTrue(description.contains("TLS"))
        assertTrue(description.contains("Test"))
    }
} 