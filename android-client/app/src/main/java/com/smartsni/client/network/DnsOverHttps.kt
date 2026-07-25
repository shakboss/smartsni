package com.smartsni.client.network

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

class DnsOverHttps(private val serverHost: String) {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val dnsUrl: String
        get() = "https://$serverHost/dns-query"

    suspend fun resolve(dnsQuery: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url(dnsUrl)
                .post(dnsQuery.toRequestBody("application/dns-message".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.bytes() ?: throw Exception("Empty DNS response")
            response.close()
            body
        } catch (e: Exception) {
            Log.e("DnsOverHttps", "DNS resolution failed: ${e.message}")
            throw e
        }
    }

    fun close() {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }
}
