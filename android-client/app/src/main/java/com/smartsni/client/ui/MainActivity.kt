package com.smartsni.client.ui

import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.textfield.TextInputEditText
import com.smartsni.client.R
import com.smartsni.client.vpn.SmartSniVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var serverHostInput: TextInputEditText
    private lateinit var wsPathInput: TextInputEditText
    private lateinit var secretInput: TextInputEditText
    private lateinit var triggerSniInput: TextInputEditText
    private lateinit var connectButton: Button
    private lateinit var statusText: TextView
    private lateinit var logText: TextView

    private val logBuilder = StringBuilder()
    private var isConnecting = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            appendLog("VPN permission denied")
            updateUI(false)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences(SmartSniVpnService.PREFS_NAME, MODE_PRIVATE)

        serverHostInput = findViewById(R.id.serverHostInput)
        wsPathInput = findViewById(R.id.wsPathInput)
        secretInput = findViewById(R.id.secretInput)
        triggerSniInput = findViewById(R.id.triggerSniInput)
        connectButton = findViewById(R.id.connectButton)
        statusText = findViewById(R.id.statusText)
        logText = findViewById(R.id.logText)

        loadSavedConfig()

        connectButton.setOnClickListener {
            if (SmartSniVpnService.isRunning) {
                stopVpn()
            } else if (!isConnecting) {
                saveConfig()
                requestVpnPermission()
            }
        }

        SmartSniVpnService.statusListener = { status ->
            runOnUiThread {
                when (status) {
                    "connected" -> updateUI(true)
                    "disconnected" -> updateUI(false)
                }
            }
        }

        updateUI(SmartSniVpnService.isRunning)
    }

    override fun onResume() {
        super.onResume()
        updateUI(SmartSniVpnService.isRunning)
    }

    private fun loadSavedConfig() {
        serverHostInput.setText(prefs.getString("server_host", "home.shaktt.xyz"))
        wsPathInput.setText(prefs.getString("ws_path", "/wstunnel"))
        secretInput.setText(prefs.getString("secret", ""))
        triggerSniInput.setText(prefs.getString("trigger_sni", "mail.shaktt.xyz"))
    }

    private fun saveConfig() {
        prefs.edit().apply {
            putString("server_host", serverHostInput.text.toString().trim())
            putString("ws_path", wsPathInput.text.toString().trim())
            putString("secret", secretInput.text.toString().trim())
            putString("trigger_sni", triggerSniInput.text.toString().trim())
            apply()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        isConnecting = true
        updateUI(false, connecting = true)
        appendLog("Starting VPN...")

        val intent = Intent(this, SmartSniVpnService::class.java).apply {
            putExtra("server_host", serverHostInput.text.toString().trim())
            putExtra("ws_path", wsPathInput.text.toString().trim())
            putExtra("bypass_secret", secretInput.text.toString().trim())
            putExtra("trigger_sni", triggerSniInput.text.toString().trim())
        }

        startForegroundService(intent)

        lifecycleScope.launch {
            delay(2000)
            isConnecting = false
            updateUI(SmartSniVpnService.isRunning)
            if (SmartSniVpnService.isRunning) {
                appendLog("VPN connected")
            } else {
                appendLog("VPN failed to start")
            }
        }
    }

    private fun stopVpn() {
        appendLog("Disconnecting...")
        val intent = Intent(this, SmartSniVpnService::class.java).apply {
            action = SmartSniVpnService.ACTION_STOP
        }
        startService(intent)
        updateUI(false)
    }

    private fun updateUI(connected: Boolean, connecting: Boolean = false) {
        runOnUiThread {
            if (connecting) {
                statusText.text = getString(R.string.connecting)
                statusText.setTextColor(getColor(R.color.accent))
                connectButton.text = getString(R.string.connecting)
                connectButton.isEnabled = false
            } else if (connected) {
                statusText.text = getString(R.string.connected)
                statusText.setTextColor(getColor(R.color.connected_green))
                connectButton.text = "Disconnect"
                connectButton.isEnabled = true
                setInputsEnabled(false)
            } else {
                statusText.text = getString(R.string.disconnected)
                statusText.setTextColor(getColor(R.color.disconnected_red))
                connectButton.text = getString(R.string.disconnected)
                connectButton.isEnabled = true
                setInputsEnabled(true)
            }
        }
    }

    private fun setInputsEnabled(enabled: Boolean) {
        serverHostInput.isEnabled = enabled
        wsPathInput.isEnabled = enabled
        secretInput.isEnabled = enabled
        triggerSniInput.isEnabled = enabled
    }

    private fun appendLog(message: String) {
        runOnUiThread {
            val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                .format(java.util.Date())
            logBuilder.appendLine("[$timestamp] $message")
            if (logBuilder.length > 2000) {
                logBuilder.delete(0, logBuilder.length - 1500)
            }
            logText.text = logBuilder.toString()
        }
    }
}
