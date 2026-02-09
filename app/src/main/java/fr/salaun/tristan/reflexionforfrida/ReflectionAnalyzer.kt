package fr.salaun.tristan.reflexionforfrida

import android.util.Log
import fr.salaun.tristan.reflexionforfrida.model.ClassModel
import fr.salaun.tristan.reflexionforfrida.model.Method
import fr.salaun.tristan.reflexionforfrida.model.Parameter
import fr.salaun.tristan.reflexionforfrida.model.Stats
import kotlin.reflect.KClass
import kotlin.reflect.KParameter
import kotlin.reflect.full.declaredFunctions
import kotlin.reflect.jvm.jvmName

/**
 * Analyzes a class using Kotlin reflection and optionally enriches the result
 * with parameter names from the Android documentation.
 */
class ReflectionAnalyzer {

    companion object {
        private const val TAG = "ReflectionAnalyzer"
    }

    /**
     * Analyze a class using reflection and match with documentation if available.
     * @return a Pair of the ClassModel and statistics about documentation matching.
     */
    fun <T : Any> analyze(
        kClass: KClass<T>,
        documentation: ClassModel?
    ): Pair<ClassModel, Stats> {
        val stats = Stats()
        val model = buildModel(kClass, documentation, stats)
        return Pair(model, stats)
    }

    private fun <T : Any> buildModel(
        kClass: KClass<T>,
        documentation: ClassModel?,
        stats: Stats
    ): ClassModel {
        Log.d(TAG, "Analyzing class: ${kClass.jvmName}")

        val constructors = buildConstructors(kClass, documentation, stats)
        val methods = buildMethods(kClass, documentation, stats)

        return ClassModel(kClass.jvmName, constructors, methods)
    }

    private fun <T : Any> buildConstructors(
        kClass: KClass<T>,
        documentation: ClassModel?,
        stats: Stats
    ): List<Method> {
        return kClass.constructors.map { constructor ->
            val docMethod = documentation?.let {
                findCorrespondingMethod(it, constructor.name, constructor.parameters, isConstructor = true, stats)
            }

            val paramList = constructor.parameters.mapIndexedNotNull { index, parameter ->
                parameter.name?.let { name ->
                    val displayName = docMethod?.parameters?.getOrNull(index)?.name ?: name
                    Parameter(displayName, TypeMapper.convertTypeFromKotlinToFrida(parameter.type.toString()))
                }
            }

            Method(constructor.name, paramList)
        }
    }

    private fun <T : Any> buildMethods(
        kClass: KClass<T>,
        documentation: ClassModel?,
        stats: Stats
    ): List<Method> {
        return kClass.declaredFunctions.map { function ->
            val docMethod = documentation?.let {
                findCorrespondingMethod(it, function.name, function.parameters, isConstructor = false, stats)
            }

            // drop(1) to skip the 'this' instance parameter
            val paramList = function.parameters.drop(1).mapIndexedNotNull { index, parameter ->
                parameter.name?.let { name ->
                    val displayName = docMethod?.parameters?.getOrNull(index)?.name ?: name
                    Parameter(displayName, TypeMapper.convertTypeFromKotlinToFrida(parameter.type.toString()))
                }
            }

            Method(function.name, paramList, function.returnType.toString())
        }
    }

    private fun findCorrespondingMethod(
        documentation: ClassModel,
        methodName: String,
        parametersList: List<KParameter>,
        isConstructor: Boolean,
        stats: Stats
    ): Method? {
        val paramsWithoutThis = if (isConstructor) parametersList else parametersList.drop(1)

        val candidates = if (isConstructor) {
            documentation.constructors.filter { it.parameters.size == paramsWithoutThis.size }
        } else {
            documentation.methods.filter { it.name == methodName && it.parameters.size == paramsWithoutThis.size }
        }

        Log.d(TAG, "findCorrespondingMethod($methodName): ${candidates.size} candidates")

        return when (candidates.size) {
            0 -> {
                stats.notFound++
                null
            }
            1 -> {
                stats.onlyOne++
                candidates[0]
            }
            else -> {
                val result = resolveOverload(paramsWithoutThis, candidates)
                if (result != null) stats.findInMany++ else stats.missInMany++
                result
            }
        }
    }

    /**
     * Resolve which overloaded method matches based on parameter types.
     */
    private fun resolveOverload(
        reflectedParams: List<KParameter>,
        candidates: List<Method>
    ): Method? {
        for (candidate in candidates) {
            val allMatch = candidate.parameters.indices.all { i ->
                val reflectedTypeName = TypeMapper.getSimpleTypeName(reflectedParams[i].type.toString())
                TypeMapper.compareTypes(candidate.parameters[i].type, reflectedTypeName)
            }
            if (allMatch) {
                Log.d(TAG, "Resolved overload: $candidate")
                return candidate
            }
        }
        return null
    }
}
