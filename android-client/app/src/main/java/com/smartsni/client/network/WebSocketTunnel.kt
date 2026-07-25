package com.smartsni.client.network

import android.util.Log
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.abs

class WebSocketTunnel(
    private var serverHost: String,
    private val wsPath: String,
    private val bypassTriggerSni: String,
    private val bypassSecret: String?,
    private val trafficShaper: TrafficShaper? = null,
    private val frontingConfig: DomainManager.FrontingConfig? = null,
    private val fallbackHosts: List<String> = emptyList()
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
    private var multiplexer: Multiplexer? = null
    private var useMultiplexing = false

    private var pendingTargetHost: String = ""
    private var pendingTargetPort: Int = 0
    private var currentFallbackIndex = 0
    private var isRetrying = false

    // Per-connection stream ID (for legacy single-stream mode)
    private var legacyStreamId = 1

    private val client: OkHttpClient
    init {
        val socketFactory = ChromeTlsFingerprint.createSocketFactory()

        // Variable ping interval: 25-45 seconds (mimics Chrome's irregular pings)
        val pingIntervalSec = 25 + random.nextInt(21)

        client = OkHttpClient.Builder()
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .writeTimeout(0, TimeUnit.MILLISECONDS)
            .pingInterval(pingIntervalSec.toLong(), TimeUnit.SECONDS)
            .sslSocketFactory(socketFactory, ChromeTlsFingerprint.trustManager)
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

        val url: String
        val hostHeader: String

        if (frontingConfig != null && frontingConfig.frontHost.isNotBlank()) {
            url = "wss://${frontingConfig.frontHost}$randomizedPath"
            hostHeader = frontingConfig.upstreamHost.ifBlank { bypassTriggerSni }
            Log.i("WS-Tunnel", "Domain fronting: URL=$url, Host=$hostHeader")
        } else {
            url = "wss://$serverHost$randomizedPath"
            hostHeader = bypassTriggerSni
            Log.i("WS-Tunnel", "Connecting to $url for $targetHost:$targetPort")
        }

        val builder = Request.Builder()
            .url(url)
            .header("Host", hostHeader)

        // Varied HTTP headers (rotate order and values slightly per connection)
        addVariedHeaders(builder)

        if (frontingConfig != null) {
            builder.header("X-Forwarded-Host", bypassTriggerSni)
        }

        if (!bypassSecret.isNullOrEmpty()) {
            builder.header("Authorization", "Bearer $bypassSecret")
        }

        webSocket = client.newWebSocket(builder.build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, response: Response) {
                Log.i("WS-Tunnel", "WebSocket opened, waiting for hello")
                isRetrying = false
            }

            override fun onMessage(ws: WebSocket, bytes: ByteString) {
                handleServerData(bytes.toByteArray())
            }

            override fun onMessage(ws: WebSocket, text: String) {
                Log.d("WS-Tunnel", "Text: $text")
                if (text.contains("\"type\"") && text.contains("\"hello\"")) {
                    // Check if server supports multiplexing
                    useMultiplexing = text.contains("\"multiplexing\":true") ||
                            text.contains("\"multiplexing\": true")
                    Log.i("WS-Tunnel", "Server hello: multiplexing=$useMultiplexing")
                    startProtocol()
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
                connected.set(false)
                if (!isRetrying && currentFallbackIndex < fallbackHosts.size) {
                    val nextHost = fallbackHosts[currentFallbackIndex++]
                    Log.w("WS-Tunnel", "Falling back to: $nextHost")
                    isRetrying = true
                    serverHost = nextHost
                    disconnect()
                    connect(pendingTargetHost, pendingTargetPort)
                } else {
                    isRetrying = false
                    listener?.onError(t.message ?: "Connection failed")
                }
            }
        })
    }

    private fun startProtocol() {
        if (useMultiplexing) {
            startMultiplexedMode()
        } else {
            startLegacyMode()
        }
    }

    private fun startMultiplexedMode() {
        val ws = webSocket ?: return
        multiplexer = Multiplexer(ws, trafficShaper)
        multiplexer?.setListener(object : Multiplexer.StreamListener {
            override fun onStreamData(streamId: Int, data: ByteArray) {
                listener?.onDataReceived(data)
            }

            override fun onStreamOpen(streamId: Int) {
                connected.set(true)
                listener?.onTunnelReady()
            }

            override fun onStreamClose(streamId: Int) {
                listener?.onDisconnected("Stream $streamId closed")
                connected.set(false)
            }

            override fun onStreamError(streamId: Int, error: String) {
                listener?.onError("Stream $streamId: $error")
            }
        })

        // Open a stream for the pending connection
        multiplexer?.openStream(pendingTargetHost, pendingTargetPort)
    }

    private fun startLegacyMode() {
        sendSocks5Greeting()
    }

    private fun sendSocks5Greeting() {
        val greeting = byteArrayOf(0x05, 0x01, 0x00)
        webSocket?.send(greeting.toByteString(0, greeting.size))
        Log.d("WS-Tunnel", "SOCKS5 greeting sent")
    }

    private fun handleServerData(data: ByteArray) {
        if (data.isEmpty()) return

        // Multiplexed mode: all frames go to multiplexer
        if (useMultiplexing) {
            multiplexer?.handleFrame(data)
            return
        }

        // Legacy mode: strip padding and handle SOCKS5
        val stripped = stripPadding(data)

        when {
            stripped.size == 2 && stripped[0] == 0x05.toByte() && stripped[1] == 0x00.toByte() -> {
                Log.d("WS-Tunnel", "SOCKS5 method selected, sending CONNECT")
                sendSocks5Connect()
            }
            stripped.size >= 10 && stripped[0] == 0x05.toByte() && stripped[1] == 0x00.toByte() -> {
                Log.i("WS-Tunnel", "SOCKS5 CONNECT success")
                connected.set(true)
                listener?.onTunnelReady()
            }
            stripped.size >= 2 && stripped[0] == 0x05.toByte() && stripped[1] != 0x00.toByte() -> {
                Log.e("WS-Tunnel", "SOCKS5 error: ${stripped[1]}")
                listener?.onError("SOCKS5 connection failed: ${stripped[1]}")
                webSocket?.close(1011, "SOCKS5 error")
            }
            else -> {
                if (connected.get()) {
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

        if (useMultiplexing) {
            return multiplexer?.sendData(legacyStreamId, data) ?: false
        }

        val ws = webSocket ?: return false
        return try {
            ws.send(data.toByteString(0, data.size))
            true
        } catch (e: Exception) {
            Log.e("WS-Tunnel", "Send failed: ${e.message}")
            false
        }
    }

    fun disconnect() {
        connected.set(false)
        if (useMultiplexing) {
            multiplexer?.closeAll()
            multiplexer = null
        }
        webSocket?.close(1000, "Disconnect")
        webSocket = null
    }

    fun isConnected(): Boolean = connected.get()

    fun cleanupStaleStreams(maxIdleMs: Long = 120_000) {
        multiplexer?.cleanupStaleStreams(maxIdleMs)
    }

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

    private fun addVariedHeaders(builder: Request.Builder) {
        // Rotate User-Agent between Chrome versions
        val chromeVersions = listOf(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        )
        val chromeVersion = chromeVersions[random.nextInt(chromeVersions.size)]
        val majorVersion = chromeVersion.substringAfter("Chrome/").substringBefore(".")

        val secChUa = "\"Google Chrome\";v=\"$majorVersion\", \"Chromium\";v=\"$majorVersion\", \"Not_A Brand\";v=\"${random.nextInt(10, 30)}\""

        builder
            .header("User-Agent", chromeVersion)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br, zstd")
            .header("Sec-Ch-Ua", secChUa)
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

        // Occasionally add extra headers that real browsers send
        if (random.nextBoolean()) {
            builder.header("Priority", "u=1, i")
        }
        if (random.nextInt(3) == 0) {
            builder.header("Sec-CH-UA-Full-Version-List", secChUa)
        }
    }
}
