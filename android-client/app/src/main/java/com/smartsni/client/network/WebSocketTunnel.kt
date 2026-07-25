package com.smartsni.client.network

import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class WebSocketTunnel(
    private val serverHost: String,
    private val wsPath: String,
    private val bypassTriggerSni: String,
    private val bypassSecret: String?,
    private val trafficShaper: TrafficShaper? = null
) {

    interface Listener {
        fun onTunnelReady()
        fun onDataReceived(data: ByteArray)
        fun onDisconnected(reason: String)
        fun onError(error: String)
    }

    private var webSocket: WebSocket? = null
    private var listener: Listener? = null
    private val connected = AtomicBoolean(false)
    private val random = SecureRandom()

    private var pendingTargetHost: String = ""
    private var pendingTargetPort: Int = 0

    private val client = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .pingInterval(30, TimeUnit.SECONDS)
        .build()

    fun setListener(listener: Listener) {
        this.listener = listener
    }

    fun connect(targetHost: String, targetPort: Int) {
        pendingTargetHost = targetHost
        pendingTargetPort = targetPort

        val url = "wss://$serverHost$wsPath"
        Log.i("WS-Tunnel", "Connecting to $url for $targetHost:$targetPort")

        val builder = Request.Builder()
            .url(url)
            .header("Host", bypassTriggerSni)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generateWebSocketKey())

        if (!bypassSecret.isNullOrEmpty()) {
            builder.header("Authorization", "Bearer $bypassSecret")
        }

        webSocket = client.newWebSocket(builder.build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i("WS-Tunnel", "WebSocket opened, waiting for server hello")
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                val rawData = bytes.toByteArray()
                val data = if (trafficShaper?.isEnabled() == true) {
                    trafficShaper.stripFrameNoise(rawData)
                } else rawData
                handleServerData(data)
            }

            override fun onMessage(ws: WebSocket, text: String) {
                Log.d("WS-Tunnel", "Text: $text")
                if (text.contains("\"type\"") && text.contains("\"hello\"")) {
                    Log.i("WS-Tunnel", "Server hello received, starting SOCKS5")
                    sendSocks5Greeting()
                }
            }

            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                ws.close(1000, null)
                listener?.onDisconnected("Closing: $reason")
                connected.set(false)
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                Log.i("WS-Tunnel", "Closed: $code $reason")
                listener?.onDisconnected("$code: $reason")
                connected.set(false)
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                Log.e("WS-Tunnel", "Failed: ${t.message}")
                listener?.onError(t.message ?: "Connection failed")
                connected.set(false)
            }
        })
    }

    private fun sendSocks5Greeting() {
        val greeting = byteArrayOf(0x05, 0x01, 0x00)
        webSocket?.send(greeting.toByteString(0, greeting.size))
        Log.d("WS-Tunnel", "SOCKS5 greeting sent")
    }

    private fun handleServerData(data: ByteArray) {
        if (data.isEmpty()) return

        when {
            data.size >= 2 && data[0] == 0x05.toByte() && data[1] == 0x00.toByte() && data.size == 3 -> {
                Log.d("WS-Tunnel", "SOCKS5 method selected, sending CONNECT")
                sendSocks5Connect()
            }
            data.size >= 2 && data[0] == 0x05.toByte() && data[1] == 0x00.toByte() && data.size >= 10 -> {
                Log.i("WS-Tunnel", "SOCKS5 CONNECT success")
                connected.set(true)
                listener?.onTunnelReady()
            }
            data.size >= 2 && data[0] == 0x05.toByte() && data[1] != 0x00.toByte() -> {
                Log.e("WS-Tunnel", "SOCKS5 error: ${data[1]}")
                listener?.onError("SOCKS5 connection failed: ${data[1]}")
                webSocket?.close(1011, "SOCKS5 error")
            }
            else -> {
                if (connected.get()) {
                    listener?.onDataReceived(data)
                }
            }
        }
    }

    private fun sendSocks5Connect() {
        val hostBytes = pendingTargetHost.toByteArray(Charsets.US_ASCII)
        val buf = ByteArrayOutputStream()
        buf.write(0x05)
        buf.write(0x01)
        buf.write(0x00)
        buf.write(0x03)
        buf.write(hostBytes.size)
        buf.write(hostBytes)
        buf.write((pendingTargetPort shr 8) and 0xFF)
        buf.write(pendingTargetPort and 0xFF)

        val connectReq = buf.toByteArray()
        webSocket?.send(connectReq.toByteString(0, connectReq.size))
        Log.d("WS-Tunnel", "SOCKS5 CONNECT sent: $pendingTargetHost:$pendingTargetPort")
    }

    fun send(data: ByteArray): Boolean {
        if (!connected.get()) return false
        val ws = webSocket ?: return false
        return try {
            val shaped = trafficShaper?.shapeOutgoing(data) ?: TrafficShaper.ShapedData(data, 0)
            val framed = trafficShaper?.addFrameNoise(shaped.payload) ?: data
            ws.send(framed.toByteString(0, framed.size))
            true
        } catch (e: Exception) {
            Log.e("WS-Tunnel", "Send failed: ${e.message}")
            false
        }
    }

    fun disconnect() {
        connected.set(false)
        webSocket?.close(1000, "Disconnect")
        webSocket = null
    }

    fun isConnected(): Boolean = connected.get()

    private fun generateWebSocketKey(): String {
        val key = ByteArray(16)
        random.nextBytes(key)
        return android.util.Base64.encodeToString(key, android.util.Base64.NO_WRAP)
    }
}
