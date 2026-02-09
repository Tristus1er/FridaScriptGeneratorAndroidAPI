package fr.salaun.tristan.reflexionforfrida

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import fr.salaun.tristan.reflexionforfrida.model.GenerationState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel : ViewModel() {

    companion object {
        private const val TAG = "MainViewModel"
    }

    private val _state = MutableStateFlow<GenerationState>(GenerationState.Idle)
    val state: StateFlow<GenerationState> = _state

    private val documentationFetcher = DocumentationFetcher()
    private val reflectionAnalyzer = ReflectionAnalyzer()
    private val scriptGenerator = FridaScriptGenerator()

    fun generate(className: String, templateName: String) {
        _state.value = GenerationState.Loading

        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    val kClass = Class.forName(className).kotlin

                    val documentation = try {
                        documentationFetcher.fetchDocumentation(kClass)
                    } catch (e: Exception) {
                        Log.w(TAG, "Documentation fetch failed for $className: ${e.message}")
                        null
                    }

                    val (model, stats) = reflectionAnalyzer.analyze(kClass, documentation)

                    val simpleClassName = className.substringAfterLast('.')
                    val script = scriptGenerator.generate(
                        model = model,
                        templateName = templateName,
                        scriptName = "observer_${simpleClassName.lowercase()}.js",
                        eventType = simpleClassName.lowercase()
                    )

                    GenerationState.Success(script, stats, className)
                }
                _state.value = result
            } catch (e: Exception) {
                Log.e(TAG, "Generation failed", e)
                _state.value = GenerationState.Error(
                    e.message ?: "Unknown error during generation"
                )
            }
        }
    }
}
