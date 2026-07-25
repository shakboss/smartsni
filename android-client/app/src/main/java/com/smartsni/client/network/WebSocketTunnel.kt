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
    private var coverTrafficJob: java.util.concurrent.ScheduledExecutorService? = null

    private var pendingTargetHost: String = ""
    private var pendingTargetPort: Int = 0

    private val client: OkHttpClient

    init {
        val socketFactory = ChromeTlsFingerprint.createSocketFactory()
        val trustManager = object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        }

        client = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .writeTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(30, TimeUnit.SECONDS)
            .sslSocketFactory(socketFactory, trustManager)
            .hostnameVerifier { _, _ -> true }
            .build()
    }

    fun setListener(listener: Listener) {
        this.listener = listener
    }

    fun connect(targetHost: String, targetPort: Int) {
        pendingTargetHost = targetHost
        pendingTargetPort = targetPort

        val randomizedPath = randomizePath(wsPath)
        val url = "wss://$serverHost$randomizedPath"
        Log.i("WS-Tunnel", "Connecting to $url for $targetHost:$targetPort")

        val builder = Request.Builder()
            .url(url)
            .header("Host", bypassTriggerSni)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .header("Sec-Ch-Ua", "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
            .header("Sec-Ch-Ua-Mobile", "?0")
            .header("Sec-Ch-Ua-Platform", "\"Windows\"")
            .header("Sec-Fetch-Dest", "websocket")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-User", "?1")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generateWebSocketKey())
            .header("Cache-Control", "max-age=0")

        if (!bypassSecret.isNullOrEmpty()) {
            builder.header("Authorization", "Bearer $bypassSecret")
        }

        webSocket = client.newWebSocket(builder.build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i("WS-Tunnel", "WebSocket opened, waiting for server hello")
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                handleServerData(bytes.toByteArray())
            }

            override fun onMessage(ws: WebSocket, text: String) {
                Log.d("WS-Tunnel", "Text: $text")
                if (text.contains("\"type\"") && text.contains("\"hello\"")) {
                    Log.i("WS-Tunnel", "Server hello received, starting SOCKS5")
                    sendSocks5Greeting()
                }
            }

            override fun onClosing(ws: WebSocket, code: Int, reason: String) {
                stopCoverTraffic()
                ws.close(1000, null)
                listener?.onDisconnected("Closing: $reason")
                connected.set(false)
            }

            override fun onClosed(ws: WebSocket, code: Int, reason: String) {
                stopCoverTraffic()
                Log.i("WS-Tunnel", "Closed: $code $reason")
                listener?.onDisconnected("$code: $reason")
                connected.set(false)
            }

            override fun onFailure(ws: WebSocket, t: Throwable, response: Response?) {
                stopCoverTraffic()
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
                startCoverTraffic()
            }
            data.size >= 2 && data[0] == 0x05.toByte() && data[1] != 0x00.toByte() -> {
                Log.e("WS-Tunnel", "SOCKS5 error: ${data[1]}")
                listener?.onError("SOCKS5 connection failed: ${data[1]}")
                webSocket?.close(1011, "SOCKS5 error")
            }
            else -> {
                if (connected.get()) {
                    val stripped = stripPadding(data)
                    if (stripped.isNotEmpty()) {
                        listener?.onDataReceived(stripped)
                    }
                }
            }
        }
    }

    private fun stripPadding(data: ByteArray): ByteArray {
        if (data.size < 4) return data
        val padSize = ((data[data.size - 4].toInt() and 0xFF) shl 24) or
                ((data[data.size - 3].toInt() and 0xFF) shl 16) or
                ((data[data.size - 2].toInt() and 0xFF) shl 8) or
                (data[data.size - 1].toInt() and 0xFF)
        if (padSize <= 0 || padSize > data.size - 4) return data
        return data.copyOfRange(0, data.size - 4 - padSize)
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
            ws.send(data.toByteString(0, data.size))
            true
        } catch (e: Exception) {
            Log.e("WS-Tunnel", "Send failed: ${e.message}")
            false
        }
    }

    private fun startCoverTraffic() {
        coverTrafficJob = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()
        coverTrafficJob?.scheduleWithFixedDelay({
            try {
                if (connected.get()) {
                    val coverData = generateCoverPayload()
                    webSocket?.send(coverData.toByteString(0, coverData.size))
                }
            } catch (e: Exception) {
                Log.d("WS-Tunnel", "Cover traffic error: ${e.message}")
            }
        }, 5, 5 + random.nextInt(10), TimeUnit.SECONDS)
    }

    private fun stopCoverTraffic() {
        coverTrafficJob?.shutdownNow()
        coverTrafficJob = null
    }

    private fun generateCoverPayload(): ByteArray {
        val type = random.nextInt(3)
        return when (type) {
            0 -> {
                val ws = webSocket
                if (ws != null) {
                    val pingData = ByteArray(4)
                    random.nextBytes(pingData)
                    pingData
                } else ByteArray(0)
            }
            1 -> {
                val heartbeat = "{\"type\":\"ping\",\"ts\":${System.currentTimeMillis()}}"
                heartbeat.toByteArray(Charsets.UTF_8)
            }
            else -> {
                val keepAlive = ByteArray(8 + random.nextInt(32))
                random.nextBytes(keepAlive)
                keepAlive
            }
        }
    }

    fun disconnect() {
        stopCoverTraffic()
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

    private fun randomizePath(basePath: String): String {
        val suffixes = listOf(
            "/api/v1/stream",
            "/ws/live",
            "/notifications",
            "/realtime",
            "/events",
            "/chat",
            "/v2/connect",
            "/socket",
            "/live/events",
            "/data/stream"
        )
        return if (random.nextBoolean()) {
            "${basePath}${suffixes[random.nextInt(suffixes.size)]}"
        } else {
            basePath
        }
    }
}
