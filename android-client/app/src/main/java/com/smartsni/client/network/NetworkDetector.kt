package com.smartsni.client.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager
import android.util.Log

class NetworkDetector(private val context: Context) {

    companion object {
        private const val TAG = "NetworkDetector"
    }

    enum class NetworkType {
        WIFI, MOBILE_4G, MOBILE_3G, MOBILE_2G, VPN, ETHERNET, UNKNOWN
    }

    interface Listener {
        fun onNetworkChanged(type: NetworkType, isMobile: Boolean)
    }

    private var listener: Listener? = null
    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private var currentNetworkType: NetworkType = NetworkType.UNKNOWN

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val type = classifyNetwork(caps)
            if (type != currentNetworkType) {
                currentNetworkType = type
                val isMobile = type == NetworkType.MOBILE_2G ||
                        type == NetworkType.MOBILE_3G ||
                        type == NetworkType.MOBILE_4G
                Log.i(TAG, "Network changed: $type (mobile=$isMobile)")
                listener?.onNetworkChanged(type, isMobile)
            }
        }

        override fun onLost(network: Network) {
            currentNetworkType = NetworkType.UNKNOWN
            listener?.onNetworkChanged(NetworkType.UNKNOWN, false)
        }
    }

    fun setListener(listener: Listener) {
        this.listener = listener
    }

    fun start() {
        val currentNetwork = connectivityManager.activeNetwork
        if (currentNetwork != null) {
            val caps = connectivityManager.getNetworkCapabilities(currentNetwork)
            if (caps != null) {
                currentNetworkType = classifyNetwork(caps)
                Log.i(TAG, "Current network: $currentNetworkType")
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            connectivityManager.registerDefaultNetworkCallback(networkCallback)
        }
    }

    fun stop() {
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister callback: ${e.message}")
        }
    }

    fun getCurrentNetworkType(): NetworkType = currentNetworkType

    fun isCurrentlyMobile(): Boolean {
        return currentNetworkType == NetworkType.MOBILE_2G ||
                currentNetworkType == NetworkType.MOBILE_3G ||
                currentNetworkType == NetworkType.MOBILE_4G
    }

    private fun classifyNetwork(caps: NetworkCapabilities): NetworkType {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return NetworkType.WIFI
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return getMobileNetworkType()
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return NetworkType.VPN
            }
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return NetworkType.ETHERNET
            }
        }
        return NetworkType.UNKNOWN
    }

    private fun getMobileNetworkType(): NetworkType {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            ?: return NetworkType.MOBILE_4G

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val dataNetworkType = tm.dataNetworkType
            return when (dataNetworkType) {
                TelephonyManager.NETWORK_TYPE_LTE -> NetworkType.MOBILE_4G
                TelephonyManager.NETWORK_TYPE_HSPAP,
                TelephonyManager.NETWORK_TYPE_UMTS,
                TelephonyManager.NETWORK_TYPE_EVDO_0,
                TelephonyManager.NETWORK_TYPE_EVDO_A,
                TelephonyManager.NETWORK_TYPE_EVDO_B -> NetworkType.MOBILE_3G
                TelephonyManager.NETWORK_TYPE_GPRS,
                TelephonyManager.NETWORK_TYPE_EDGE,
                TelephonyManager.NETWORK_TYPE_1xRTT,
                TelephonyManager.NETWORK_TYPE_IDEN -> NetworkType.MOBILE_2G
                TelephonyManager.NETWORK_TYPE_NR -> NetworkType.MOBILE_4G
                else -> NetworkType.MOBILE_4G
            }
        }

        @Suppress("DEPRECATION")
        val networkType = tm.networkType
        @Suppress("DEPRECATION")
        return when (networkType) {
            TelephonyManager.NETWORK_TYPE_LTE -> NetworkType.MOBILE_4G
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_UMTS -> NetworkType.MOBILE_3G
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE -> NetworkType.MOBILE_2G
            else -> NetworkType.MOBILE_4G
        }
    }
}
