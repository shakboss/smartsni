package com.smartsni.client.network

import java.security.SecureRandom

class TrafficShaper(
    private val delayMsRange: IntRange = 5..200,
    private val jitterEnabled: Boolean = true
) {

    private val random = SecureRandom()
    private var enabled = true

    fun setEnabled(enabled: Boolean) {
        this.enabled = enabled
    }

    fun isEnabled(): Boolean = enabled

    data class ShapedData(
        val payload: ByteArray,
        val delayMs: Long
    )

    /**
     * Bimodal distribution: 80% of packets get < 5ms delay (fast),
     * 20% get 50-200ms delay (mimics real browser buffering patterns).
     */
    fun shapeOutgoing(data: ByteArray): ShapedData {
        if (!enabled || data.isEmpty()) {
            return ShapedData(data, 0)
        }

        val delay = if (jitterEnabled) {
            bimodalDelayMs()
        } else 0

        return ShapedData(data, delay)
    }

    fun shapeIncoming(data: ByteArray): ShapedData {
        if (!enabled || data.isEmpty()) {
            return ShapedData(data, 0)
        }

        val delay = if (jitterEnabled) {
            bimodalDelayMs()
        } else 0

        return ShapedData(data, delay)
    }

    private fun bimodalDelayMs(): Long {
        return if (random.nextDouble() < 0.80) {
            // 80% fast (< 5ms)
            random.nextLong(0, 5)
        } else {
            // 20% slow (50-200ms)
            val min = maxOf(delayMsRange.first.toLong(), 50)
            val max = maxOf(delayMsRange.last.toLong(), 200)
            random.nextLong(min, max + 1)
        }
    }
}
