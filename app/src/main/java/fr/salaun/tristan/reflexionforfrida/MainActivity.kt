package fr.salaun.tristan.reflexionforfrida

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.RadioGroup
import android.widget.TextView
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.button.MaterialButton
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.textfield.TextInputEditText
import fr.salaun.tristan.reflexionforfrida.model.GenerationState
import fr.salaun.tristan.reflexionforfrida.model.Stats
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()

    private lateinit var etClassName: TextInputEditText
    private lateinit var rgTemplate: RadioGroup
    private lateinit var btnGenerate: MaterialButton
    private lateinit var btnCopy: MaterialButton
    private lateinit var btnShare: MaterialButton
    private lateinit var tvStats: TextView
    private lateinit var tvOutput: TextView
    private lateinit var progressBar: ProgressBar

    private var currentScript: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bindViews()
        setupListeners()
        observeState()
    }

    private fun bindViews() {
        etClassName = findViewById(R.id.etClassName)
        rgTemplate = findViewById(R.id.rgTemplate)
        btnGenerate = findViewById(R.id.btnGenerate)
        btnCopy = findViewById(R.id.btnCopy)
        btnShare = findViewById(R.id.btnShare)
        tvStats = findViewById(R.id.tvStats)
        tvOutput = findViewById(R.id.tvOutput)
        progressBar = findViewById(R.id.progressBar)
    }

    private fun setupListeners() {
        btnGenerate.setOnClickListener {
            val className = etClassName.text?.toString()?.trim()
            if (className.isNullOrEmpty()) {
                etClassName.error = getString(R.string.error_empty_class)
                return@setOnClickListener
            }

            val templateName = when (rgTemplate.checkedRadioButtonId) {
                R.id.rbConsole -> "frida_script.ftl"
                else -> "frida_script_events.ftl"
            }

            viewModel.generate(className, templateName)
        }

        btnCopy.setOnClickListener {
            currentScript?.let { script ->
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Frida Script", script))
                Snackbar.make(btnCopy, R.string.copied_to_clipboard, Snackbar.LENGTH_SHORT).show()
            }
        }

        btnShare.setOnClickListener {
            currentScript?.let { script ->
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, script)
                    putExtra(Intent.EXTRA_SUBJECT, "Frida Script")
                }
                startActivity(Intent.createChooser(shareIntent, getString(R.string.share_script)))
            }
        }
    }

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.state.collect { state ->
                    when (state) {
                        is GenerationState.Idle -> showIdle()
                        is GenerationState.Loading -> showLoading()
                        is GenerationState.Success -> showSuccess(state.script, state.stats, state.className)
                        is GenerationState.Error -> showError(state.message)
                    }
                }
            }
        }
    }

    private fun showIdle() {
        progressBar.visibility = View.GONE
        btnGenerate.isEnabled = true
        btnCopy.isEnabled = false
        btnShare.isEnabled = false
    }

    private fun showLoading() {
        progressBar.visibility = View.VISIBLE
        btnGenerate.isEnabled = false
        btnCopy.isEnabled = false
        btnShare.isEnabled = false
        tvStats.text = ""
        tvOutput.text = getString(R.string.generating)
    }

    private fun showSuccess(script: String, stats: Stats, className: String) {
        currentScript = script
        progressBar.visibility = View.GONE
        btnGenerate.isEnabled = true
        btnCopy.isEnabled = true
        btnShare.isEnabled = true

        tvStats.text = getString(
            R.string.stats_format,
            className.substringAfterLast('.'),
            stats.matched,
            stats.total,
            stats.notFound,
            stats.missInMany
        )

        tvOutput.text = script
    }

    private fun showError(message: String) {
        currentScript = null
        progressBar.visibility = View.GONE
        btnGenerate.isEnabled = true
        btnCopy.isEnabled = false
        btnShare.isEnabled = false
        tvStats.text = ""
        tvOutput.text = getString(R.string.error_format, message)

        Snackbar.make(tvOutput, message, Snackbar.LENGTH_LONG).show()
    }
}
