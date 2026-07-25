package com.smartsni.client.network

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.smartsni.client.vpn.SmartSniVpnService
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList

class DomainManager(context: Context) {

    companion object {
        private const val TAG = "DomainManager"
        private const val PREFS_NAME = SmartSniVpnService.PREFS_NAME
    }

    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val random = SecureRandom()

    private val domains = CopyOnWriteArrayList<String>()
    private var currentIndex = 0
    private var frontingEnabled = false
    private var frontHost = ""
    private var frontSni = ""
    private var upstreamHost = ""

    data class DomainConfig(
        val primary: String,
        val fallbacks: List<String>,
        val fronting: FrontingConfig?
    )

    data class FrontingConfig(
        val frontHost: String,
        val frontSni: String,
        val upstreamHost: String
    )

    fun loadFromPrefs() {
        val savedDomains = prefs.getString("trigger_domains", null)
        if (!savedDomains.isNullOrBlank()) {
            domains.clear()
            savedDomains.split(",").forEach { d ->
                val trimmed = d.trim()
                if (trimmed.isNotBlank()) domains.add(trimmed)
            }
        }

        val primary = prefs.getString("server_host", "") ?: ""
        if (domains.isEmpty() && primary.isNotBlank()) {
            domains.add(primary)
        }

        frontingEnabled = prefs.getBoolean("fronting_enabled", false)
        frontHost = prefs.getString("front_host", "") ?: ""
        frontSni = prefs.getString("front_sni", "") ?: ""
        upstreamHost = prefs.getString("upstream_host", "") ?: ""

        currentIndex = prefs.getInt("domain_index", 0) % maxOf(domains.size, 1)
        Log.i(TAG, "Loaded ${domains.size} domains, current=$currentIndex, fronting=$frontingEnabled")
    }

    fun saveToPrefs(primary: String, fallbacks: List<String>, fronting: FrontingConfig?) {
        val allDomains = mutableListOf(primary) + fallbacks
        domains.clear()
        allDomains.filter { it.isNotBlank() }.forEach { domains.add(it) }
        currentIndex = 0

        prefs.edit().apply {
            putString("trigger_domains", allDomains.joinToString(","))
            putInt("domain_index", currentIndex)
            fronting?.let {
                putBoolean("fronting_enabled", true)
                putString("front_host", it.frontHost)
                putString("front_sni", it.frontSni)
                putString("upstream_host", it.upstreamHost)
            } ?: run {
                putBoolean("fronting_enabled", false)
            }
            apply()
        }
        Log.i(TAG, "Saved ${domains.size} domains, fronting=${fronting != null}")
    }

    fun getCurrentDomain(): String {
        if (domains.isEmpty()) return prefs.getString("server_host", "") ?: ""
        return domains[currentIndex % domains.size]
    }

    fun getFallbackDomains(): List<String> {
        if (domains.size <= 1) return emptyList()
        val result = mutableListOf<String>()
        for (i in domains.indices) {
            if (i != currentIndex % domains.size) {
                result.add(domains[i])
            }
        }
        return result
    }

    fun rotateToNext(): String {
        if (domains.size <= 1) return getCurrentDomain()
        currentIndex = (currentIndex + 1) % domains.size
        prefs.edit().putInt("domain_index", currentIndex).apply()
        val domain = domains[currentIndex]
        Log.i(TAG, "Rotated to domain: $domain")
        return domain
    }

    fun markFailed(domain: String) {
        Log.w(TAG, "Domain marked as failed: $domain")
        if (domains.size > 1) {
            rotateToNext()
        }
    }

    fun markSuccess(domain: String) {
        val idx = domains.indexOf(domain)
        if (idx >= 0) {
            currentIndex = idx
            prefs.edit().putInt("domain_index", currentIndex).apply()
        }
    }

    fun isFrontingEnabled(): Boolean = frontingEnabled
    fun getFrontHost(): String = frontHost
    fun getFrontSni(): String = frontSni
    fun getUpstreamHost(): String = upstreamHost

    fun getFrontingConfig(): FrontingConfig? {
        return if (frontingEnabled && frontHost.isNotBlank() && frontSni.isNotBlank()) {
            FrontingConfig(frontHost, frontSni, upstreamHost)
        } else null
    }

    fun getAllDomains(): List<String> = domains.toList()
}
