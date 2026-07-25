package com.smartsni.client.network

import android.util.Log
import java.security.SecureRandom

class TrafficShaper(
    private val paddingRange: IntRange = 10..100,
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

        val padded = addPadding(data)
        val delay = if (jitterEnabled) {
            random.nextLong(delayMsRange.first.toLong(), delayMsRange.last.toLong() + 1)
        } else 0

        return ShapedData(padded, delay)
    }

    fun shapeIncoming(data: ByteArray): ShapedData {
        if (!enabled || data.isEmpty()) {
            return ShapedData(data, 0)
        }

        val stripped = stripPadding(data)
        val delay = if (jitterEnabled) {
            random.nextLong(delayMsRange.first.toLong(), delayMsRange.last.toLong() + 1)
        } else 0

        return ShapedData(stripped, delay)
    }

    private fun addPadding(data: ByteArray): ByteArray {
        val padSize = random.nextInt(paddingRange.first, paddingRange.last + 1)
        if (padSize <= 0) return data

        val padded = ByteArray(data.size + padSize + 4)
        System.arraycopy(data, 0, padded, 0, data.size)

        padded[data.size] = ((padSize shr 24) and 0xFF).toByte()
        padded[data.size + 1] = ((padSize shr 16) and 0xFF).toByte()
        padded[data.size + 2] = ((padSize shr 8) and 0xFF).toByte()
        padded[data.size + 3] = (padSize and 0xFF).toByte()

        for (i in 0 until padSize) {
            padded[data.size + 4 + i] = random.nextInt(256).toByte()
        }

        return padded
    }

    private fun stripPadding(data: ByteArray): ByteArray {
        if (data.size < 4) return data

        val padSize = ((data[data.size - 4].toInt() and 0xFF) shl 24) or
                ((data[data.size - 3].toInt() and 0xFF) shl 16) or
                ((data[data.size - 2].toInt() and 0xFF) shl 8) or
                (data[data.size - 1].toInt() and 0xFF)

        if (padSize <= 0 || padSize > data.size - 4) return data

        val expectedSize = data.size - 4 - padSize
        return data.copyOfRange(0, expectedSize)
    }

    fun addFrameNoise(data: ByteArray): ByteArray {
        if (!enabled) return data

        val noiseByte = random.nextInt(256).toByte()
        val framed = ByteArray(1 + data.size)
        framed[0] = noiseByte
        System.arraycopy(data, 0, framed, 1, data.size)
        return framed
    }

    fun stripFrameNoise(data: ByteArray): ByteArray {
        if (!enabled || data.isEmpty()) return data
        return data.copyOfRange(1, data.size)
    }
}
