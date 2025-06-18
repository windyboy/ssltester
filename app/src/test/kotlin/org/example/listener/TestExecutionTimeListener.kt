package org.example.listener

import org.junit.platform.engine.TestExecutionResult
import org.junit.platform.launcher.TestExecutionListener
import org.junit.platform.launcher.TestIdentifier
import org.junit.platform.launcher.TestPlan
import java.util.concurrent.ConcurrentHashMap

class TestExecutionTimeListener : TestExecutionListener {
    private val testTimes = ConcurrentHashMap<String, Long>()
    private val testStartTimes = ConcurrentHashMap<String, Long>()

    override fun testPlanExecutionStarted(testPlan: TestPlan) {
        println("\n=== Starting Test Execution ===\n")
    }

    override fun testPlanExecutionFinished(testPlan: TestPlan) {
        println("\n=== Test Execution Summary ===")
        testTimes.entries.sortedByDescending { it.value }.forEach { (testName, time) ->
            println("$testName took ${time}ms")
        }
        println("\n=== End of Test Execution ===\n")
    }

    override fun executionStarted(testIdentifier: TestIdentifier) {
        if (testIdentifier.isTest) {
            testStartTimes[testIdentifier.uniqueId] = System.currentTimeMillis()
        }
    }

    override fun executionFinished(
        testIdentifier: TestIdentifier,
        result: TestExecutionResult,
    ) {
        if (testIdentifier.isTest) {
            val startTime = testStartTimes.remove(testIdentifier.uniqueId)
            if (startTime != null) {
                val duration = System.currentTimeMillis() - startTime
                testTimes[testIdentifier.displayName] = duration
            }
        }
    }
}
