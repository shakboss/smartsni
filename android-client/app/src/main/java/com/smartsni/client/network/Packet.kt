package com.smartsni.client.network

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class IpHeader(
    val version: Int,
    val ihl: Int,
    val totalLength: Int,
    val protocol: Int,
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val payloadOffset: Int
) {
    companion object {
        const val TCP = 6
        const val UDP = 17

        fun parse(data: ByteArray, offset: Int = 0): IpHeader? {
            if (data.size - offset < 20) return null
            val versionIhl = data[offset].toInt() and 0xFF
            val version = versionIhl shr 4
            if (version != 4) return null
            val ihl = versionIhl and 0x0F
            if (ihl < 5) return null
            val totalLength = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + 3].toInt() and 0xFF)
            val protocol = data[offset + 9].toInt() and 0xFF
            val srcIp = data.copyOfRange(offset + 12, offset + 16)
            val dstIp = data.copyOfRange(offset + 16, offset + 20)
            return IpHeader(version, ihl, totalLength, protocol, srcIp, dstIp, offset + ihl * 4)
        }
    }

    val srcIpString: String get() = srcIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
    val dstIpString: String get() = dstIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
}

data class TcpHeader(
    val srcPort: Int,
    val dstPort: Int,
    val seq: Long,
    val ack: Long,
    val dataOffset: Int,
    val flags: Int,
    val window: Int,
    val payloadOffset: Int,
    val payloadSize: Int
) {
    companion object {
        const val FIN = 0x01
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10

        fun parse(data: ByteArray, offset: Int): TcpHeader? {
            if (data.size - offset < 20) return null
            val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
            val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + 3].toInt() and 0xFF)
            val seq = ((data[offset + 4].toInt() and 0xFF).toLong() shl 24) or
                    ((data[offset + 5].toInt() and 0xFF).toLong() shl 16) or
                    ((data[offset + 6].toInt() and 0xFF).toLong() shl 8) or
                    (data[offset + 7].toInt() and 0xFF).toLong()
            val ack = ((data[offset + 8].toInt() and 0xFF).toLong() shl 24) or
                    ((data[offset + 9].toInt() and 0xFF).toLong() shl 16) or
                    ((data[offset + 10].toInt() and 0xFF).toLong() shl 8) or
                    (data[offset + 11].toInt() and 0xFF).toLong()
            val dataOffset = (data[offset + 12].toInt() and 0xF0) shr 4
            if (dataOffset < 5) return null
            val flags = data[offset + 13].toInt() and 0xFF
            val window = ((data[offset + 14].toInt() and 0xFF) shl 8) or
                    (data[offset + 15].toInt() and 0xFF)
            val headerEnd = offset + dataOffset * 4
            val totalIpLength = run {
                val b = data
                ((b[offset - 2].toInt() and 0xFF) shl 8) or (b[offset - 1].toInt() and 0xFF)
            }
            val ipHeaderLen = offset
            val payloadSize = totalIpLength - ipHeaderLen - dataOffset * 4
            return TcpHeader(srcPort, dstPort, seq, ack, dataOffset, flags, window,
                headerEnd, maxOf(0, payloadSize))
        }
    }

    val isSyn: Boolean get() = (flags and SYN) != 0
    val isAck: Boolean get() = (flags and ACK) != 0
    val isFin: Boolean get() = (flags and FIN) != 0
    val isRst: Boolean get() = (flags and RST) != 0
    val isPsh: Boolean get() = (flags and PSH) != 0
}

data class UdpHeader(
    val srcPort: Int,
    val dstPort: Int,
    val length: Int
) {
    companion object {
        fun parse(data: ByteArray, offset: Int): UdpHeader? {
            if (data.size - offset < 8) return null
            val srcPort = ((data[offset].toInt() and 0xFF) shl 8) or
                    (data[offset + 1].toInt() and 0xFF)
            val dstPort = ((data[offset + 2].toInt() and 0xFF) shl 8) or
                    (data[offset + 3].toInt() and 0xFF)
            val length = ((data[offset + 4].toInt() and 0xFF) shl 8) or
                    (data[offset + 5].toInt() and 0xFF)
            return UdpHeader(srcPort, dstPort, length)
        }
    }
}

object PacketBuilder {
    fun buildIpHeader(
        srcIp: ByteArray, dstIp: ByteArray,
        protocol: Int, payloadLength: Int,
        identification: Int = (Math.random() * 65535).toInt()
    ): ByteArray {
        val ihl = 5
        val totalLength = ihl * 4 + payloadLength
        val header = ByteArray(ihl * 4)
        header[0] = 0x45.toByte()
        header[1] = 0x00
        header[2] = (identification shr 8).toByte()
        header[3] = (identification and 0xFF).toByte()
        header[4] = (totalLength shr 8).toByte()
        header[5] = (totalLength and 0xFF).toByte()
        header[6] = 0x40.toByte() // Don't fragment
        header[7] = 0x00
        header[8] = 0x40 // TTL
        header[9] = protocol.toByte()
        // Checksum placeholder (0)
        header[10] = 0x00
        header[11] = 0x00
        System.arraycopy(srcIp, 0, header, 12, 4)
        System.arraycopy(dstIp, 0, header, 16, 4)
        val checksum = calculateChecksum(header)
        header[10] = (checksum shr 8).toByte()
        header[11] = (checksum and 0xFF).toByte()
        return header
    }

    fun buildTcpHeader(
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, window: Int = 65535,
        payload: ByteArray = byteArrayOf()
    ): ByteArray {
        val dataOffset = 5
        val header = ByteArray(dataOffset * 4)
        header[0] = (srcPort shr 8).toByte()
        header[1] = (srcPort and 0xFF).toByte()
        header[2] = (dstPort shr 8).toByte()
        header[3] = (dstPort and 0xFF).toByte()
        header[4] = (seq shr 24).toByte()
        header[5] = (seq shr 16).toByte()
        header[6] = (seq shr 8).toByte()
        header[7] = seq.toByte()
        header[8] = (ack shr 24).toByte()
        header[9] = (ack shr 16).toByte()
        header[10] = (ack shr 8).toByte()
        header[11] = ack.toByte()
        header[12] = ((dataOffset shl 4) and 0xFF).toByte()
        header[13] = flags.toByte()
        header[14] = (window shr 8).toByte()
        header[15] = (window and 0xFF).toByte()
        // Checksum and urgent pointer
        header[16] = 0x00
        header[17] = 0x00
        header[18] = 0x00
        header[19] = 0x00
        return header
    }

    fun buildTcpPacket(
        srcIp: ByteArray, dstIp: ByteArray,
        srcPort: Int, dstPort: Int,
        seq: Long, ack: Long,
        flags: Int, window: Int = 65535,
        payload: ByteArray = byteArrayOf()
    ): ByteArray {
        val tcpHeader = buildTcpHeader(srcPort, dstPort, seq, ack, flags, window, payload)
        val ipHeader = buildIpHeader(srcIp, dstIp, IpHeader.TCP, tcpHeader.size + payload.size)
        val packet = ByteArray(ipHeader.size + tcpHeader.size + payload.size)
        System.arraycopy(ipHeader, 0, packet, 0, ipHeader.size)
        System.arraycopy(tcpHeader, 0, packet, ipHeader.size, tcpHeader.size)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, packet, ipHeader.size + tcpHeader.size, payload.size)
        }
        // TCP checksum over pseudo-header
        val pseudoHeader = ByteArray(12 + tcpHeader.size + payload.size)
        System.arraycopy(srcIp, 0, pseudoHeader, 0, 4)
        System.arraycopy(dstIp, 0, pseudoHeader, 4, 4)
        pseudoHeader[8] = 0x00
        pseudoHeader[9] = IpHeader.TCP.toByte()
        val tcpLen = tcpHeader.size + payload.size
        pseudoHeader[10] = (tcpLen shr 8).toByte()
        pseudoHeader[11] = (tcpLen and 0xFF).toByte()
        System.arraycopy(tcpHeader, 0, pseudoHeader, 12, tcpHeader.size)
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, pseudoHeader, 12 + tcpHeader.size, payload.size)
        }
        val tcpChecksum = calculateChecksum(pseudoHeader)
        packet[ipHeader.size + 16] = (tcpChecksum shr 8).toByte()
        packet[ipHeader.size + 17] = (tcpChecksum and 0xFF).toByte()
        return packet
    }

    fun calculateChecksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < data.size - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (data.size % 2 == 1) {
            sum += (data[data.size - 1].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.toInt().inv() and 0xFFFF
    }
}
