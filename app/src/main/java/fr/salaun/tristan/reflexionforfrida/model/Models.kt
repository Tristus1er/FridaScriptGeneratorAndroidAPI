package fr.salaun.tristan.reflexionforfrida.model

data class Parameter(val name: String, val type: String)

data class Method(
    val name: String,
    val parameters: List<Parameter>,
    val returnType: String? = null
)

data class ClassModel(
    val name: String,
    val constructors: List<Method>,
    val methods: List<Method>
)

data class Stats(
    var notFound: Int = 0,
    var onlyOne: Int = 0,
    var findInMany: Int = 0,
    var missInMany: Int = 0
) {
    val total: Int get() = notFound + onlyOne + findInMany + missInMany
    val matched: Int get() = onlyOne + findInMany

    fun reset() {
        notFound = 0
        onlyOne = 0
        findInMany = 0
        missInMany = 0
    }
}

sealed class GenerationState {
    data object Idle : GenerationState()
    data object Loading : GenerationState()
    data class Success(
        val script: String,
        val stats: Stats,
        val className: String
    ) : GenerationState()
    data class Error(val message: String) : GenerationState()
}
