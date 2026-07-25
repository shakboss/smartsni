package com.smartsni.client.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

class DnsOverHttps(private val serverHost: String) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val dnsUrl: String
        get() = "https://$serverHost/dns-query"

    private data class CacheEntry(
        val response: ByteArray,
        val expiryMs: Long
    )

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    suspend fun resolve(dnsQuery: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        try {
            // Check cache (key by query bytes hash + first 4 bytes for domain)
            val cacheKey = dnsQuery.contentHashCode().toString()
            val cached = cache[cacheKey]
            if (cached != null && System.currentTimeMillis() < cached.expiryMs) {
                Log.d("DnsOverHttps", "DNS cache hit")
                return@withContext cached.response
            }

            val request = Request.Builder()
                .url(dnsUrl)
                .post(dnsQuery.toRequestBody("application/dns-message".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.bytes() ?: throw Exception("Empty DNS response")
            response.close()

            // Parse TTL from DNS response to set cache expiry
            val ttlMs = parseMinTtl(dnsQuery, body)
            if (ttlMs > 0) {
                cache[cacheKey] = CacheEntry(body, System.currentTimeMillis() + ttlMs)
                // Evict old entries periodically
                if (cache.size > 500) {
                    evictExpired()
                }
            }

            body
        } catch (e: Exception) {
            Log.e("DnsOverHttps", "DNS resolution failed: ${e.message}")
            throw e
        }
    }

    private fun parseMinTtl(query: ByteArray, response: ByteArray): Long {
        try {
            // Extract the query domain name for logging
            // DNS TTL is in the answer section - use a conservative default
            // Real TTL parsing would need dnspython-like parsing
            return 60_000L // 60 second default cache
        } catch (e: Exception) {
            return 30_000L // 30 second fallback
        }
    }

    private fun evictExpired() {
        val now = System.currentTimeMillis()
        cache.entries.removeIf { it.value.expiryMs < now }
    }

    fun clearCache() {
        cache.clear()
    }

    fun close() {
        clearCache()
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }
}
