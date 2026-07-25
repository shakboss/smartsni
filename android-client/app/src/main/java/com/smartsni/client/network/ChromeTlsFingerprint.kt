package com.smartsni.client.network

import android.os.Build
import android.util.Log
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

object ChromeTlsFingerprint {

    private const val TAG = "ChromeTLS"

    val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out java.security.cert.X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
    }

    private val CHROME_CIPHER_SUITES = intArrayOf(
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02b, // ECDHE_ECDSA_AES_128_GCM_SHA256
        0xc02f, // ECDHE_RSA_AES_128_GCM_SHA256
        0xc02c, // ECDHE_ECDSA_AES_256_GCM_SHA384
        0xc030, // ECDHE_RSA_AES_256_GCM_SHA384
        0xcca9, // ECDHE_ECDSA_CHACHA20_POLY1305
        0xcca8, // ECDHE_RSA_CHACHA20_POLY1305
        0xc013, // ECDHE_RSA_AES_128_CBC_SHA
        0xc014, // ECDHE_RSA_AES_256_CBC_SHA
        0x009c, // RSA_AES_128_GCM_SHA256
        0x009d, // RSA_AES_256_GCM_SHA384
        0x009f, // RSA_AES_128_CBC_SHA256
        0x0035, // RSA_AES_256_CBC_SHA256
        0x0033, // RSA_AES_128_CBC_SHA
        0x0039  // RSA_AES_256_CBC_SHA
    )

    private val CIPHER_NAME_MAP = mapOf(
        0x1301 to "TLS_AES_128_GCM_SHA256",
        0x1302 to "TLS_AES_256_GCM_SHA384",
        0x1303 to "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b to "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc02f to "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02c to "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xc030 to "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xcca9 to "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0xcca8 to "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xc013 to "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xc014 to "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009c to "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d to "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x009f to "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x0035 to "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x0033 to "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0039 to "TLS_RSA_WITH_AES_256_CBC_SHA"
    )

    fun createSocketFactory(): SSLSocketFactory {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), SecureRandom())

        return object : SSLSocketFactory() {
            override fun getDefaultCipherSuites(): Array<String> = emptyArray()
            override fun getSupportedCipherSuites(): Array<String> = emptyArray()

            override fun createSocket(s: java.net.Socket?, host: String?, port: Int, autoClose: Boolean): java.net.Socket {
                val socket = sslContext.socketFactory.createSocket(s, host, port, autoClose)
                configureSocket(socket as SSLSocket)
                return socket
            }

            override fun createSocket(host: String?, port: Int): java.net.Socket {
                val socket = sslContext.socketFactory.createSocket(host, port)
                configureSocket(socket as SSLSocket)
                return socket
            }

            override fun createSocket(host: String?, port: Int, localHost: java.net.InetAddress?, localPort: Int): java.net.Socket {
                val socket = sslContext.socketFactory.createSocket(host, port, localHost, localPort)
                configureSocket(socket as SSLSocket)
                return socket
            }

            override fun createSocket(host: java.net.InetAddress?, port: Int): java.net.Socket {
                val socket = sslContext.socketFactory.createSocket(host, port)
                configureSocket(socket as SSLSocket)
                return socket
            }

            override fun createSocket(address: java.net.InetAddress?, port: Int, localAddress: java.net.InetAddress?, localPort: Int): java.net.Socket {
                val socket = sslContext.socketFactory.createSocket(address, port, localAddress, localPort)
                configureSocket(socket as SSLSocket)
                return socket
            }
        }
    }

    private fun configureSocket(sslSocket: SSLSocket) {
        try {
            val params = sslSocket.sslParameters

            params.cipherSuites = CHROME_CIPHER_SUITES.mapNotNull { cipherId ->
                CIPHER_NAME_MAP[cipherId]
            }.toTypedArray()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                params.setAlgorithmConstraints(null)
            }

            sslSocket.sslParameters = params
            sslSocket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
            sslSocket.enabledCipherSuites = params.cipherSuites

            Log.d(TAG, "TLS configured: ${params.cipherSuites?.size} ciphers, protocols: ${params.protocols?.contentToString()}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to configure TLS: ${e.message}")
        }
    }
}
