package com.smartsni.client.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.smartsni.client.R
import com.smartsni.client.network.*
import com.smartsni.client.ui.MainActivity
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

class SmartSniVpnService : VpnService() {

    companion object {
        private const val TAG = "SmartSniVPN"
        private const val CHANNEL_ID = "smartsni_vpn"
        private const val NOTIFICATION_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_MASK = "0"
        const val PREFS_NAME = "smartsni_prefs"
        const val ACTION_STOP = "com.smartsni.client.STOP_VPN"

        var isRunning = false
            private set
        var statusListener: ((String) -> Unit)? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnelJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var serverHost = ""
    private var wsPath = "/wstunnel"
    private var bypassTriggerSni = ""
    private var bypassSecret = ""

    private var dnsResolver: DnsOverHttps? = null

    private val tcpConnections = ConcurrentHashMap<String, TcpSession>()

    private enum class TcpState {
        SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED
    }

    private data class TcpSession(
        val srcIp: ByteArray,
        val srcPort: Int,
        val dstIp: String,
        val dstPort: Int,
        var localSeq: Long,
        var remoteSeq: Long,
        var state: TcpState,
        val wsTunnel: WebSocketTunnel,
        val dataQueue: LinkedBlockingQueue<ByteArray> = LinkedBlockingQueue(),
        var dataWriter: FileOutputStream? = null
    )

    private fun connKey(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int) =
        "$srcIp:$srcPort-$dstIp:$dstPort"

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        serverHost = intent?.getStringExtra("server_host") ?: ""
        wsPath = intent?.getStringExtra("ws_path") ?: "/wstunnel"
        bypassTriggerSni = intent?.getStringExtra("trigger_sni") ?: ""
        bypassSecret = intent?.getStringExtra("bypass_secret") ?: ""

        if (serverHost.isEmpty()) {
            Log.e(TAG, "No server host provided")
            stopSelf()
            return START_NOT_STICKY
        }

        startVpn()

        val stopIntent = Intent(this, SmartSniVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 0, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val openIntent = Intent(this, MainActivity::class.java)
        val openPending = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("SmartSNI VPN")
            .setContentText("Connected to $serverHost")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(
                Notification.Action.Builder(
                    null, "Disconnect", stopPending
                ).build()
            )
            .build()

        startForeground(NOTIFICATION_ID, notification)
        statusListener?.invoke("connected")

        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        val builder = Builder()
            .setSession("SmartSNI")
            .setMtu(1500)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, VPN_MASK)
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .setBlocking(true)

        try {
            vpnInterface = builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN: ${e.message}")
            stopSelf()
            return
        }

        if (vpnInterface == null) {
            Log.e(TAG, "VPN interface is null")
            stopSelf()
            return
        }

        isRunning = true
        dnsResolver = DnsOverHttps(serverHost)

        tunnelJob = scope.launch {
            runTunnel()
        }
    }

    private suspend fun runTunnel() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val inputStream = FileInputStream(fd)
        val outputStream = FileOutputStream(fd)

        val packet = ByteArray(32767)

        withContext(Dispatchers.IO) {
            while (isActive && isRunning) {
                try {
                    val length = inputStream.read(packet)
                    if (length <= 0) continue

                    val ipHeader = IpHeader.parse(packet, 0) ?: continue

                    when (ipHeader.protocol) {
                        IpHeader.UDP -> handleUdp(packet, ipHeader, outputStream)
                        IpHeader.TCP -> handleTcp(packet, ipHeader, outputStream)
                    }
                } catch (e: CancellationException) {
                    break
                } catch (e: Exception) {
                    if (isRunning) {
                        Log.e(TAG, "Tunnel error: ${e.message}")
                    }
                }
            }

            inputStream.close()
            outputStream.close()
        }
    }

    private suspend fun handleUdp(
        packet: ByteArray,
        ipHeader: IpHeader,
        outputStream: FileOutputStream
    ) {
        val udpHeader = UdpHeader.parse(packet, ipHeader.payloadOffset) ?: return
        val dnsOffset = ipHeader.payloadOffset + 8

        if (udpHeader.dstPort == 53) {
            val dnsQuery = packet.copyOfRange(dnsOffset, ipHeader.payloadOffset + udpHeader.length)
            try {
                val dnsResponse = dnsResolver?.resolve(dnsQuery) ?: return
                val udpPayloadLen = dnsResponse.size
                val ipPkt = PacketBuilder.buildIpHeader(
                    ipHeader.dstIp, ipHeader.srcIp,
                    IpHeader.UDP, 8 + udpPayloadLen
                )
                val udpHdr = ByteArray(8)
                udpHdr[0] = (udpHeader.dstPort shr 8).toByte()
                udpHdr[1] = (udpHeader.dstPort and 0xFF).toByte()
                udpHdr[2] = (udpHeader.srcPort shr 8).toByte()
                udpHdr[3] = (udpHeader.srcPort and 0xFF).toByte()
                udpHdr[4] = ((8 + udpPayloadLen) shr 8).toByte()
                udpHdr[5] = ((8 + udpPayloadLen) and 0xFF).toByte()

                val response = ByteArray(ipPkt.size + 8 + udpPayloadLen)
                System.arraycopy(ipPkt, 0, response, 0, ipPkt.size)
                System.arraycopy(udpHdr, 0, response, ipPkt.size, 8)
                System.arraycopy(dnsResponse, 0, response, ipPkt.size + 8, udpPayloadLen)
                outputStream.write(response)
                outputStream.flush()
                Log.d(TAG, "DNS response sent: ${dnsResponse.size} bytes")
            } catch (e: Exception) {
                Log.e(TAG, "DNS DoH failed: ${e.message}")
            }
        }
    }

    private fun handleTcp(
        packet: ByteArray,
        ipHeader: IpHeader,
        outputStream: FileOutputStream
    ) {
        val tcpHeader = TcpHeader.parse(packet, ipHeader.payloadOffset) ?: return
        val payload = if (tcpHeader.payloadSize > 0 && tcpHeader.payloadOffset + tcpHeader.payloadSize <= packet.size) {
            packet.copyOfRange(tcpHeader.payloadOffset, tcpHeader.payloadOffset + tcpHeader.payloadSize)
        } else byteArrayOf()

        val key = connKey(
            ipHeader.srcIpString, tcpHeader.srcPort,
            ipHeader.dstIpString, tcpHeader.dstPort
        )

        if (tcpHeader.isSyn && !tcpHeader.isAck) {
            handleSyn(key, ipHeader, tcpHeader, outputStream)
            return
        }

        val session = tcpConnections[key] ?: return

        if (tcpHeader.isRst) {
            Log.d(TAG, "RST for $key")
            cleanupSession(key, session)
            sendTcpSegment(outputStream, session, ipHeader.dstIp, ipHeader.srcIp,
                tcpHeader.dstPort, tcpHeader.srcPort, TcpHeader.RST)
            return
        }

        if (tcpHeader.isFin) {
            Log.d(TAG, "FIN for $key")
            session.remoteSeq = tcpHeader.seq + 1
            sendTcpSegment(outputStream, session, ipHeader.dstIp, ipHeader.srcIp,
                tcpHeader.dstPort, tcpHeader.srcPort, TcpHeader.ACK or TcpHeader.FIN)
            session.localSeq++
            cleanupSession(key, session)
            return
        }

        if (tcpHeader.isAck && session.state == TcpState.SYN_RECEIVED) {
            Log.i(TAG, "Handshake complete for $key")
            session.state = TcpState.ESTABLISHED
            startRelay(key, session, ipHeader, outputStream)
            return
        }

        if (payload.isNotEmpty() && session.state == TcpState.ESTABLISHED) {
            session.remoteSeq = tcpHeader.seq + payload.size
            sendTcpSegment(outputStream, session, ipHeader.dstIp, ipHeader.srcIp,
                tcpHeader.dstPort, tcpHeader.srcPort, TcpHeader.ACK)

            if (!session.wsTunnel.send(payload)) {
                Log.e(TAG, "WS send failed for $key")
                cleanupSession(key, session)
            }
        }
    }

    private fun handleSyn(
        key: String,
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        outputStream: FileOutputStream
    ) {
        val existing = tcpConnections[key]
        if (existing != null && existing.state != TcpState.CLOSED) {
            Log.d(TAG, "SYN retransmit for $key, resending SYN-ACK")
            sendTcpSegment(outputStream, existing, ipHeader.dstIp, ipHeader.srcIp,
                tcpHeader.dstPort, tcpHeader.srcPort,
                TcpHeader.SYN or TcpHeader.ACK)
            return
        }

        Log.i(TAG, "SYN: $key -> ${ipHeader.dstIpString}:${tcpHeader.dstPort}")

        val localSeq = (Math.random() * 4294967295L).toLong()
        val remoteSeq = tcpHeader.seq + 1

        val wsTunnel = WebSocketTunnel(serverHost, wsPath, bypassTriggerSni, bypassSecret)

        val session = TcpSession(
            srcIp = ipHeader.srcIp.copyOf(),
            srcPort = tcpHeader.srcPort,
            dstIp = ipHeader.dstIpString,
            dstPort = tcpHeader.dstPort,
            localSeq = localSeq,
            remoteSeq = remoteSeq,
            state = TcpState.SYN_RECEIVED,
            wsTunnel = wsTunnel
        )
        session.dataWriter = outputStream
        tcpConnections[key] = session

        sendTcpSegment(outputStream, session, ipHeader.dstIp, ipHeader.srcIp,
            tcpHeader.dstPort, tcpHeader.srcPort, TcpHeader.SYN or TcpHeader.ACK)
        session.localSeq++

        wsTunnel.setListener(object : WebSocketTunnel.Listener {
            override fun onTunnelReady() {
                Log.i(TAG, "Tunnel ready for $key")
            }

            override fun onDataReceived(data: ByteArray) {
                val writer = session.dataWriter ?: return
                sendTcpSegment(writer, session, ipHeader.dstIp, session.srcIp,
                    session.dstPort, session.srcPort, TcpHeader.ACK or TcpHeader.PSH, data)
                session.localSeq += data.size
            }

            override fun onDisconnected(reason: String) {
                Log.d(TAG, "Tunnel disconnected for $key: $reason")
                val writer = session.dataWriter ?: return
                sendTcpSegment(writer, session, ipHeader.dstIp, session.srcIp,
                    session.dstPort, session.srcPort, TcpHeader.FIN or TcpHeader.ACK)
                session.localSeq++
                cleanupSession(key, session)
            }

            override fun onError(error: String) {
                Log.e(TAG, "Tunnel error for $key: $error")
                val writer = session.dataWriter ?: return
                sendTcpSegment(writer, session, ipHeader.dstIp, session.srcIp,
                    session.dstPort, session.srcPort, TcpHeader.RST)
                cleanupSession(key, session)
            }
        })

        wsTunnel.connect(ipHeader.dstIpString, tcpHeader.dstPort)
    }

    private fun startRelay(
        key: String,
        session: TcpSession,
        ipHeader: IpHeader,
        outputStream: FileOutputStream
    ) {
        session.dataWriter = outputStream
    }

    private fun sendTcpSegment(
        outputStream: FileOutputStream,
        session: TcpSession,
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        flags: Int,
        payload: ByteArray = byteArrayOf()
    ) {
        try {
            val pkt = PacketBuilder.buildTcpPacket(
                srcIp, dstIp, srcPort, dstPort,
                session.localSeq, session.remoteSeq,
                flags, payload = payload
            )
            outputStream.write(pkt)
            outputStream.flush()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send TCP: ${e.message}")
        }
    }

    private fun sendTcpSegment(
        outputStream: FileOutputStream,
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        flags: Int,
        seq: Long = 0, ack: Long = 0,
        payload: ByteArray = byteArrayOf()
    ) {
        try {
            val pkt = PacketBuilder.buildTcpPacket(
                srcIp, dstIp, srcPort, dstPort,
                seq, ack, flags, payload = payload
            )
            outputStream.write(pkt)
            outputStream.flush()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send TCP: ${e.message}")
        }
    }

    private fun cleanupSession(key: String, session: TcpSession) {
        session.state = TcpState.CLOSED
        session.wsTunnel.disconnect()
        tcpConnections.remove(key)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_desc)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        isRunning = false
        statusListener?.invoke("disconnected")

        tunnelJob?.cancel()
        scope.cancel()

        tcpConnections.values.forEach { session ->
            session.wsTunnel.disconnect()
        }
        tcpConnections.clear()

        dnsResolver?.close()
        vpnInterface?.close()
        vpnInterface = null

        super.onDestroy()
    }
}
