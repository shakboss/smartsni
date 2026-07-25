package com.smartsni.client.network

import android.util.Log
import okhttp3.WebSocket
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class Multiplexer(
    private val webSocket: WebSocket,
    private val padding: TrafficShaper? = null
) {
    companion object {
        private const val TAG = "MuxClient"
        const val FRAME_HDR_SIZE = 9

        const val FRAME_TYPE_NEW_STREAM = 0x01
        const val FRAME_TYPE_DATA = 0x02
        const val FRAME_TYPE_CLOSE = 0x03
        const val FRAME_TYPE_FIN = 0x04
    }

    interface StreamListener {
        fun onStreamData(streamId: Int, data: ByteArray)
        fun onStreamOpen(streamId: Int)
        fun onStreamClose(streamId: Int)
        fun onStreamError(streamId: Int, error: String)
    }

    private val nextStreamId = AtomicInteger(1)
    private val streams = ConcurrentHashMap<Int, StreamState>()
    private var listener: StreamListener? = null
    private val sendLock = Any()

    private data class StreamState(
        val id: Int,
        val targetHost: String,
        val targetPort: Int,
        var connected: Boolean = false,
        val createdAt: Long = System.currentTimeMillis(),
        var lastActivity: AtomicLong = AtomicLong(System.currentTimeMillis())
    )

    fun setListener(listener: StreamListener) {
        this.listener = listener
    }

    fun openStream(host: String, port: Int): Int {
        val streamId = nextStreamId.getAndIncrement()
        val state = StreamState(streamId, host, port)
        streams[streamId] = state

        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val payload = ByteArrayOutputStream()
        payload.write(hostBytes.size)
        payload.write(hostBytes)
        payload.write((port shr 8) and 0xFF)
        payload.write(port and 0xFF)

        sendFrame(FRAME_TYPE_NEW_STREAM, streamId, payload.toByteArray())
        Log.i(TAG, "Opened stream $streamId -> $host:$port")
        return streamId
    }

    fun sendData(streamId: Int, data: ByteArray): Boolean {
        val state = streams[streamId]
        if (state == null || !state.connected) return false
        state.lastActivity.set(System.currentTimeMillis())
        sendFrame(FRAME_TYPE_DATA, streamId, data)
        return true
    }

    fun closeStream(streamId: Int) {
        streams.remove(streamId)
        sendFrame(FRAME_TYPE_CLOSE, streamId, byteArrayOf())
        Log.d(TAG, "Closed stream $streamId")
    }

    fun sendFin(streamId: Int) {
        sendFrame(FRAME_TYPE_FIN, streamId, byteArrayOf())
    }

    fun handleFrame(data: ByteArray) {
        if (data.size < FRAME_HDR_SIZE) return

        val frameType = data[0].toInt() and 0xFF
        val streamId = ((data[1].toInt() and 0xFF) shl 24) or
                ((data[2].toInt() and 0xFF) shl 16) or
                ((data[3].toInt() and 0xFF) shl 8) or
                (data[4].toInt() and 0xFF)
        val frameLen = ((data[5].toInt() and 0xFF) shl 24) or
                ((data[6].toInt() and 0xFF) shl 16) or
                ((data[7].toInt() and 0xFF) shl 8) or
                (data[8].toInt() and 0xFF)
        val payload = if (frameLen > 0 && data.size >= FRAME_HDR_SIZE + frameLen) {
            data.copyOfRange(FRAME_HDR_SIZE, FRAME_HDR_SIZE + frameLen)
        } else byteArrayOf()

        when (frameType) {
            FRAME_TYPE_NEW_STREAM -> {
                val state = streams[streamId]
                if (state != null && payload.isNotEmpty()) {
                    val status = payload[0].toInt() and 0xFF
                    if (status == 0x00) {
                        state.connected = true
                        state.lastActivity.set(System.currentTimeMillis())
                        listener?.onStreamOpen(streamId)
                        Log.i(TAG, "Stream $streamId connected")
                    } else {
                        streams.remove(streamId)
                        listener?.onStreamError(streamId, "Server rejected connection")
                        Log.e(TAG, "Stream $streamId rejected")
                    }
                }
            }
            FRAME_TYPE_DATA -> {
                val state = streams[streamId]
                if (state != null) {
                    state.lastActivity.set(System.currentTimeMillis())
                    listener?.onStreamData(streamId, payload)
                }
            }
            FRAME_TYPE_FIN -> {
                streams.remove(streamId)
                listener?.onStreamClose(streamId)
                Log.d(TAG, "Stream $streamId FIN")
            }
            FRAME_TYPE_CLOSE -> {
                streams.remove(streamId)
                listener?.onStreamClose(streamId)
                Log.d(TAG, "Stream $streamId closed by server")
            }
        }
    }

    fun getStaleStreams(maxIdleMs: Long = 120_000): List<Int> {
        val now = System.currentTimeMillis()
        return streams.entries
            .filter { now - it.value.lastActivity.get() > maxIdleMs }
            .map { it.key }
    }

    fun cleanupStaleStreams(maxIdleMs: Long = 120_000) {
        getStaleStreams(maxIdleMs).forEach { streamId ->
            Log.d(TAG, "Cleaning stale stream $streamId")
            closeStream(streamId)
        }
    }

    fun activeStreamCount(): Int = streams.size

    fun closeAll() {
        for ((id, _) in streams) {
            sendFrame(FRAME_TYPE_CLOSE, id, byteArrayOf())
        }
        streams.clear()
    }

    private fun sendFrame(type: Int, streamId: Int, payload: ByteArray) {
        synchronized(sendLock) {
            try {
                val hdr = ByteArray(FRAME_HDR_SIZE)
                hdr[0] = type.toByte()
                hdr[1] = (streamId shr 24).toByte()
                hdr[2] = (streamId shr 16).toByte()
                hdr[3] = (streamId shr 8).toByte()
                hdr[4] = streamId.toByte()
                hdr[5] = (payload.size shr 24).toByte()
                hdr[6] = (payload.size shr 16).toByte()
                hdr[7] = (payload.size shr 8).toByte()
                hdr[8] = payload.size.toByte()

                val frame = hdr + payload
                webSocket.send(frame.toByteString(0, frame.size))
            } catch (e: Exception) {
                Log.e(TAG, "Send frame error: ${e.message}")
            }
        }
    }
}
