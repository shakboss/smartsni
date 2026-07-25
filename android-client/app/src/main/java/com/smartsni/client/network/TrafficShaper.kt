package com.smartsni.client.network

import android.util.Log
import java.security.SecureRandom

class TrafficShaper(
    private val delayMsRange: IntRange = 5..20,
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

    fun shapeOutgoing(data: ByteArray): ShapedData {
        if (!enabled || data.isEmpty()) {
            return ShapedData(data, 0)
        }

        val delay = if (jitterEnabled) {
            random.nextLong(delayMsRange.first.toLong(), delayMsRange.last.toLong() + 1)
        } else 0

        return ShapedData(data, delay)
    }

    fun shapeIncoming(data: ByteArray): ShapedData {
        if (!enabled || data.isEmpty()) {
            return ShapedData(data, 0)
        }

        val delay = if (jitterEnabled) {
            random.nextLong(delayMsRange.first.toLong(), delayMsRange.last.toLong() + 1)
        } else 0

        return ShapedData(data, delay)
    }
}
