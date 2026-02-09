package fr.salaun.tristan.reflexionforfrida

import android.util.Log
import fr.salaun.tristan.reflexionforfrida.model.ClassModel
import fr.salaun.tristan.reflexionforfrida.model.Method
import fr.salaun.tristan.reflexionforfrida.model.Parameter
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlin.reflect.KClass
import kotlin.reflect.jvm.jvmName

/**
 * Fetches and parses Android API documentation from developer.android.com.
 * Extracts constructor and method signatures with parameter names.
 */
class DocumentationFetcher {

    companion object {
        private const val TAG = "DocumentationFetcher"
        private const val BASE_URL = "https://developer.android.com/reference"
        private const val CONNECT_TIMEOUT = 10_000
        private const val READ_TIMEOUT = 10_000
    }

    /**
     * Fetch documentation for the given class and parse it into a ClassModel.
     * @throws Exception if the network request or parsing fails.
     */
    fun <T : Any> fetchDocumentation(kClass: KClass<T>): ClassModel {
        val url = "$BASE_URL/${kClass.jvmName.replace('.', '/')}"
        Log.d(TAG, "Fetching documentation from: $url")
        val html = fetchHtml(url)
        return parseHtml(html, kClass.jvmName)
    }

    private fun fetchHtml(url: String): String {
        val connection = URL(url).openConnection() as HttpsURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = CONNECT_TIMEOUT
        connection.readTimeout = READ_TIMEOUT
        return connection.inputStream.bufferedReader().use { it.readText() }
    }

    private fun parseHtml(html: String, className: String): ClassModel {
        val doc = Jsoup.parse(html)
        val constructors = parseConstructors(doc)
        val methods = parseMethods(doc)
        Log.d(TAG, "Parsed $className: ${constructors.size} constructors, ${methods.size} methods")
        return ClassModel(className, constructors, methods)
    }

    private fun parseConstructors(doc: Document): List<Method> {
        val constructors = mutableListOf<Method>()
        val elements = doc.select("#proctors td[width=100%]")

        for (element in elements) {
            parseMethodElement(element)?.let { method ->
                Log.d(TAG, "Constructor: ${method.name}(${method.parameters.joinToString { "${it.type} ${it.name}" }})")
                constructors.add(method)
            }
        }
        return constructors
    }

    private fun parseMethods(doc: Document): List<Method> {
        val methods = mutableListOf<Method>()
        val elements = doc.select("#pubmethods td[width=100%]")

        for (element in elements) {
            parseMethodElement(element)?.let { method ->
                Log.d(TAG, "Method: ${method.name}(${method.parameters.joinToString { "${it.type} ${it.name}" }})")
                methods.add(method)
            }
        }
        return methods
    }

    private fun parseMethodElement(element: Element): Method? {
        return try {
            val internalDoc = Jsoup.parse(element.html())
            val body = internalDoc.body()

            // Navigate to method definition: look for first element with <a> tag
            val methodDef = body.selectFirst("code") ?: body.child(0)?.child(0) ?: return null
            val linkElement = methodDef.getElementsByTag("a").firstOrNull() ?: return null
            val methodName = linkElement.text()

            val parameters = parseParametersFromText(methodDef.text())
            Method(methodName, parameters)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse method element: ${e.message}")
            null
        }
    }

    private fun parseParametersFromText(text: String): List<Parameter> {
        val regex = "\\(([^)]+)\\)".toRegex()
        val match = regex.find(text) ?: return emptyList()

        return match.groupValues[1].split(",").mapNotNull { param ->
            val parts = param.trim().split("\\s+".toRegex())
            if (parts.size >= 2) {
                Parameter(name = parts[1], type = parts[0])
            } else {
                Log.w(TAG, "Could not parse parameter: '$param'")
                null
            }
        }
    }
}
