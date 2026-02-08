package fr.salaun.tristan.reflexionforfrida

import android.annotation.SuppressLint
import android.os.Bundle
import android.os.StrictMode
import android.util.Log
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import freemarker.template.Configuration
import freemarker.template.TemplateExceptionHandler
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.select.Elements
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.StringWriter
import java.net.URL
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.reflect.KClass
import kotlin.reflect.KParameter
import kotlin.reflect.full.declaredFunctions
import kotlin.reflect.jvm.jvmName


class MainActivity : AppCompatActivity() {
    companion object {
        private const val TAG = "MainActivity"
        private const val OUTPUT_FILENAME = "observer_crypto.js"
        private const val OUTPUT_EVENT_TYPE = "crypto"
//        private const val OUTPUT_TEMPLATE = "frida_script.ftl"
        private const val OUTPUT_TEMPLATE = "frida_script_events.ftl"
    }

    // Class to get statistics
    data class Stats(
        var notFound: Int = 0,
        var onlyOne: Int = 0,
        var findInMany: Int = 0,
        var missInMany: Int = 0
    )

    // Data classes to handle the model.
    data class Parameter(val name: String, val type: String)
    data class Method(
        val name: String,
        val parameters: List<Parameter>,
        val returnType: String? = null
    )
    data class Model(val name: String, val constructors: List<Method>, val methods: List<Method>)

    private val stats = Stats()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val edContent = findViewById<EditText>(R.id.content)

        val myClassKClass: KClass<Cipher> = javax.crypto.Cipher::class
//        val myClassKClass: KClass<KeyGenerator> = javax.crypto.KeyGenerator::class
//        val myClassKClass: KClass<KeyPairGenerator> = java.security.KeyPairGenerator::class
//        val myClassKClass: KClass<SecretKeySpec> = javax.crypto.spec.SecretKeySpec::class
//        val myClassKClass: KClass<MessageDigest> = java.security.MessageDigest::class
//        val myClassKClass: KClass<SecretKeyFactory> = javax.crypto.SecretKeyFactory::class
//        val myClassKClass: KClass<TelephonyManager> = android.telephony.TelephonyManager::class
//        val myClassKClass: KClass<String> = String::class
//        val myClassKClass: KClass<System> = java.lang.System::class

        val documentationClass = getDocumentationOfClass(myClassKClass)

        // Generate the data model
        val model = classToModel(myClassKClass, documentationClass)

        // Configure FreeMarker
        val cfg = Configuration(Configuration.VERSION_2_3_33).apply {
            setClassForTemplateLoading(this::class.java, "/assets/templates")
            defaultEncoding = "UTF-8"
            templateExceptionHandler = TemplateExceptionHandler.RETHROW_HANDLER
            objectWrapper = AndroidSafeObjectWrapper(Configuration.VERSION_2_3_33)
//            logTemplateExceptions = false
//            wrapUncheckedExceptions = true
//            fallbackOnNullLoopVariable = false
        }

        // Load the FreeMarker template.
        val template = cfg.getTemplate(OUTPUT_TEMPLATE)

        // Prepare the data to inject.
        val dataModel = mapOf("model" to model, "scriptName" to OUTPUT_FILENAME, "eventType" to OUTPUT_EVENT_TYPE)

        // Generate the output with the template.
        val out = StringWriter()
        template.process(dataModel, out)

        // Display the content generated.
        edContent.setText(out.toString())
    }

    // Get documentation from web site.
    private fun <T : Any> getDocumentationOfClass(myClassKClass: KClass<T>): Model {

        // Remove error : android.os.NetworkOnMainThreadException
        val policy = StrictMode.ThreadPolicy.Builder().permitAll().build()
        StrictMode.setThreadPolicy(policy)

        val documentationURL =
            "https://developer.android.com/reference/${myClassKClass.jvmName.replace('.', '/')}"
        val content = getHTMLContent(documentationURL)

        if (content.isNullOrEmpty()) {
            Log.w(TAG, "onCreate() getHTMLContent return null for $documentationURL")
        }

        val doc: Document = Jsoup.parse(content)

        // Store the constructors list.
        val constructors = mutableListOf<Method>()

        val constructorsMethods: Elements = doc.select("#proctors td[width=100%]")
        for (currentMethod in constructorsMethods) {
            //println(headline.html())

            val internalDoc: Document = Jsoup.parse(currentMethod.html())
            // JSoup add html, header, ...
            val methodDefinition = internalDoc.child(0).child(1).child(0)

            // method name
            val methodName = methodDefinition.getElementsByTag("a")[0].text()
            Log.d(TAG, "C - * $methodName")
            val regex = "\\(([^)]+)\\)".toRegex()
            val matches = regex.find(methodDefinition.text())
            val paramList = matches?.groupValues?.get(1)
            val paramListSplit = paramList?.split(",")

            val parameters = mutableListOf<Parameter>()
            if (paramListSplit != null) {
                for (param in paramListSplit) {
                    val paramSplit = param.trim().split(" ")
                    val type = paramSplit[0]
                    val name = paramSplit[1]
                    Log.d(TAG, "C -   - $name: $type")
                    parameters.add(Parameter(name, type))
                }
            } else {
                Log.d(TAG, "C - NO PARAMETERS")
            }

            constructors.add(Method(methodName, parameters))
        }

        // ****************************************************************************************************
        // Store the methods list.
        val methods = mutableListOf<Method>()

        val publicMethods: Elements = doc.select("#pubmethods td[width=100%]")
        for (currentMethod in publicMethods) {
            //println(headline.html())

            val internalDoc: Document = Jsoup.parse(currentMethod.html())
            // JSoup add html, header, ...
            val methodDefinition = internalDoc.child(0).child(1).child(0)

            // method name
            val methodName = methodDefinition.getElementsByTag("a")[0].text()
            Log.d(TAG, "M - * $methodName")
            val regex = "\\(([^)]+)\\)".toRegex()
            val matches = regex.find(methodDefinition.text())
            val paramList = matches?.groupValues?.get(1)
            val paramListSplit = paramList?.split(",")

            val parameters = mutableListOf<Parameter>()
            if (paramListSplit != null) {
                for (param in paramListSplit) {
                    val paramSplit = param.trim().split(" ")
                    val type = paramSplit[0]
                    val name = paramSplit[1]
                    Log.d(TAG, "M -   - $name: $type")
                    parameters.add(Parameter(name, type))
                }
            } else {
                Log.d(TAG, "M - NO PARAMETERS")
            }

            methods.add(Method(methodName, parameters))
        }

        val documentationClass = Model(myClassKClass.jvmName, constructors, methods)

        return documentationClass
    }

    // Get the HTML content of the URL.
    private fun getHTMLContent(documentationURL: String): String {
        Log.d(TAG, "getHTMLContent() called with: documentationURL = [$documentationURL]")

        try {
            // Step 1: Disable SSL certificate validation
            disableSSLCertificateChecking()

            // Step 2: Establish connection
            val url = URL(documentationURL)
            val connection = url.openConnection() as HttpsURLConnection
            connection.requestMethod = "GET"

            // Step 3: Read the HTML content from the response
            val reader = BufferedReader(InputStreamReader(connection.inputStream))
            val content = StringBuilder()

            var line: String?
            while (reader.readLine().also { line = it } != null) {
                content.append(line)
            }

            // Close the reader and disconnect
            reader.close()
            connection.disconnect()

            // Step 4: Output the HTML content
            println("HTML Content: $content")
            return content.toString()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return ""
    }

    // Method to disable SSL certificate validation
    private fun disableSSLCertificateChecking() {
        try {
            val trustAllCerts = arrayOf<TrustManager>(@SuppressLint("CustomX509TrustManager")
            object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate>? = null

                @SuppressLint("TrustAllX509TrustManager")
                override fun checkClientTrusted(
                    certs: Array<X509Certificate>,
                    authType: String
                ) {
                }

                @SuppressLint("TrustAllX509TrustManager")
                override fun checkServerTrusted(
                    certs: Array<X509Certificate>,
                    authType: String
                ) {
                }
            })

            val sc = SSLContext.getInstance("SSL")
            sc.init(null, trustAllCerts, java.security.SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.socketFactory)

            // Disable hostname verification
            HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }

        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // Keep only part of the type name.
    private fun getGoodType(rawName: String): String {
        if (rawName.contains('.')) {
            val typeArray = rawName.split(".")
            // Keep only the last part of the type, and keep only alphanumeric characters.
            return typeArray.last().replace("[^A-Za-z0-9 ]".toRegex(), "")
        } else {
            return rawName
        }
    }

    // Handle similar types.
    private fun compareTypes(firstType: String, secondType: String): Boolean {
        // First is documentation type
        // Second is reflected type
        Log.d(TAG, "compareTypes() firstType = [$firstType], secondType = [$secondType]")

        if (firstType == secondType) {
            return true
        } else {
            return when (firstType) {
                "byte[]" -> when (secondType) {
                    "ByteBuffer" -> true
                    "ByteArray" -> true
                    else -> {
                        Log.d(TAG, "compareTypes() byte[] compare")
                        false
                    }
                }

                "int" -> when (secondType) {
                    "Int" -> true
                    else -> {
                        Log.d(TAG, "compareTypes() int compare")
                        false
                    }
                }

                "byte" -> when (secondType) {
                    "Byte" -> true
                    else -> {
                        Log.d(TAG, "compareTypes() byte compare")
                        false
                    }
                }

                else -> {
                    Log.d(TAG, "compareTypes() NOT HANDLED $firstType compare")
                    false
                }
            }
        }
    }

    // Get the matching method.
    private fun getTheGoodOne(
        parametersList: List<KParameter>,
        methodsCandidates: List<Method>
    ): Method? {

        methodsCandidates.forEach { currentMethodsCandidate ->
            var counter = 0
            for (currentParameter in currentMethodsCandidate.parameters) {
                val typeName = getGoodType(parametersList[counter].type.toString())
                if (!compareTypes(currentParameter.type, typeName)) {
                    Log.d(
                        "COMPARE",
                        "${currentParameter.name}: ${currentParameter.type} != $typeName"
                    )
                    continue
                } else {
                    counter++
                    Log.d(
                        "COMPARE",
                        "${currentParameter.name}: ${currentParameter.type} MATCH $typeName"
                    )
                    if (counter == currentMethodsCandidate.parameters.size) {
                        Log.d("COMPARE", "FOUND $currentMethodsCandidate")
                        return currentMethodsCandidate
                    }
                }
            }
        }
        return null
    }

    // Try to find the documentation method corresponding to the reflexion one.
    private fun findCorrespondingMethod(
        documentationClass: Model,
        methodName: String,
        parametersList: List<KParameter>,
        isConstructor: Boolean
    ): Method? {
        Log.d(
            TAG,
            "findCorrespondingMethod() called with: documentationClass = [...], methodName = [$methodName], parametersList = [$parametersList], isConstructor = [$isConstructor]"
        )

        // Remove the first item that is the "this" parameter, in case of a function call.
        val parametersListWithoutType = if(isConstructor) {parametersList} else {parametersList.drop(1)}

        // In case of Constructor, the name is not relevant.
        val methodsCandidates = if(isConstructor) {
            documentationClass.constructors.filter { it.parameters.size == parametersListWithoutType.size }
        }else {
            documentationClass.methods.filter { it.name == methodName && it.parameters.size == parametersListWithoutType.size }
        }

        Log.d(
            TAG,
            "findCorrespondingMethod() methodsCandidates(${methodsCandidates.size}) $methodsCandidates"
        )
        return when (methodsCandidates.size) {
            0 -> {
                stats.notFound++
                null
            }

            1 -> {
                stats.onlyOne++
                methodsCandidates[0]
            }

            else -> {
                val returnValue = getTheGoodOne(parametersListWithoutType, methodsCandidates)
                if (returnValue != null) {
                    stats.findInMany++
                } else {
                    stats.missInMany++
                }
                returnValue
            }
        }
    }

    // Handle reflexion of the class, and return a simple model of it.
    // If documentation if found, then add the names of the parameters.
    private fun <T : Any> classToModel(
        myClassKClass: KClass<T>,
        documentationClass: Model?
    ): Model {

        Log.d(TAG,
            "handleClass() called with: myClassKClass = [$myClassKClass], documentationClass = [$documentationClass]"
        )

        val constructorsList = mutableListOf<Method>()

        myClassKClass.constructors.forEach {

            val documentationMethod: Method? =
                if (documentationClass != null) {
                    findCorrespondingMethod(documentationClass, it.name, it.parameters, isConstructor = true)
                } else {
                    null
                }

            Log.d(TAG, "handleClass() ${it.name} => documentationMethod = $documentationMethod")

            val paramList = mutableListOf<Parameter>()

            it.parameters.forEachIndexed { index, parameter ->
                if (!parameter.name.isNullOrEmpty()) {
                    // sb.append("Parameter: ${parameter.name} ${parameter.index} ${parameter.type} -> ${convertTypeFromKotlinToFrida(parameter.type.toString())}")
                    parameter.name?.let { parameterNameSafe ->
                        // OLD WAY: paramNameList.add(parameterNameSafe)
                        // New way : get the name from documentation
                        val parameterNamePimped = if (documentationMethod != null) {
                            documentationMethod.parameters[index].name
                        } else {
                            parameterNameSafe
                        }

                        paramList.add(
                            Parameter(
                                parameterNamePimped,
                                convertTypeFromKotlinToFrida(parameter.type.toString())
                            )
                        )
                    }
                }
            }

            constructorsList.add(Method(it.name, paramList))

        } // End constructors handling.

        // ************************************************
        // ********** Methods handling ********************
        // ************************************************

        val methodsList = mutableListOf<Method>()

        myClassKClass.declaredFunctions.forEach {

            val documentationMethod: Method? =
                if (documentationClass != null) {
                    findCorrespondingMethod(documentationClass, it.name, it.parameters, isConstructor = false)
                } else {
                    null
                }

            Log.d(TAG, "handleClass() ${it.name} => documentationMethod = $documentationMethod")

            val paramList = mutableListOf<Parameter>()

            // drop(1) : cause the first one is the instance.
            it.parameters.drop(1).forEachIndexed { index, parameter ->
                if (!parameter.name.isNullOrEmpty()) {
                    // sb.append("Parameter: ${parameter.name} ${parameter.index} ${parameter.type} -> ${convertTypeFromKotlinToFrida(parameter.type.toString())}")
                    parameter.name?.let { parameterNameSafe ->
                        // OLD WAY: paramNameList.add(parameterNameSafe)
                        // New way : get the name from documentation
                        val parameterNamePimped = if (documentationMethod != null) {
                            documentationMethod.parameters[index].name
                        } else {
                            parameterNameSafe
                        }

                        paramList.add(
                            Parameter(
                                parameterNamePimped,
                                convertTypeFromKotlinToFrida(parameter.type.toString())
                            )
                        )
                    }
                }
            }

            methodsList.add(Method(it.name, paramList, it.returnType.toString()))
        }

        val model = Model(myClassKClass.jvmName, constructorsList, methodsList)

        return model
    }

    /**
     * Match the Kotlin type to Frida type.
     * @param kotlinTypeName The Kotlin type from reflexion.
     * @return The corresponding Frida type.
     */
    private fun convertTypeFromKotlinToFrida(kotlinTypeName: String): String {
        return when (kotlinTypeName) {
            "kotlin.ByteArray" -> "[B"
            "kotlin.ByteArray!" -> "[B"

            "kotlin.Array<kotlin.Boolean>" -> "[Ljava.lang.Boolean;"
            "kotlin.Array<kotlin.Byte>" -> "[Ljava.lang.Byte;"
            "kotlin.Array<kotlin.Char>" -> "[Ljava.lang.Character;"
            "kotlin.Array<kotlin.Double>" -> "[Ljava.lang.Double;"
            "kotlin.Array<kotlin.Float>" -> "[Ljava.lang.Float;"
            "kotlin.Array<kotlin.Int>" -> "[Ljava.lang.Integer;"
            "kotlin.Array<kotlin.Long>" -> "[Ljava.lang.Long;"
            "kotlin.Array<kotlin.Short>" -> "[Ljava.lang.Short;"
            "kotlin.Array<kotlin.String>" -> "[Ljava.lang.String;"
            "kotlin.Array<kotlin.UByte>" -> "[Lkotlin.UByte;"
            "kotlin.Array<kotlin.UInt>" -> "[Lkotlin.UInt;"
            "kotlin.Array<kotlin.ULong>" -> "[Lkotlin.ULong;"
            "kotlin.Array<kotlin.UShort>" -> "[Lkotlin.UShort;"
            "kotlin.Boolean" -> "boolean"
            "kotlin.Byte" -> "byte"
            "kotlin.Char" -> "char"
            "kotlin.Double" -> "double"
            "kotlin.Float" -> "float"
            "kotlin.Int" -> "int"
            "kotlin.Int!" -> "int"
            "kotlin.Long" -> "long"
            "kotlin.Short" -> "short"
            "kotlin.String" -> "java.lang.String"
            "kotlin.String!" -> "java.lang.String"
            "kotlin.UByte" -> "???"
            "kotlin.UInt" -> "???"
            "kotlin.ULong" -> "???"
            "kotlin.UShort" -> "???"
            "kotlin.BooleanArray" -> "[Ljava.lang.Boolean;"
            "kotlin.CharArray" -> "[Ljava.lang.Character;"
            "kotlin.DoubleArray" -> "[Ljava.lang.Double;"
            "kotlin.FloatArray" -> "[Ljava.lang.Float;"
            "kotlin.IntArray" -> "[Ljava.lang.Integer;"
            "kotlin.LongArray" -> "[Ljava.lang.Long;"
            "kotlin.ShortArray" -> "[Ljava.lang.Short;"
            "kotlin.ULongArray" -> "[Lkotlin.ULong;"
            "kotlin.UShortArray" -> "[Lkotlin.UShort;"
            "kotlin.UByteArray" -> "[Lkotlin.UByte;"
            "kotlin.UIntArray" -> "[Lkotlin.UInt;"
            "kotlin.Any?" -> "java.lang.Object"
            // kotlin.Unit

            else -> if (kotlinTypeName.endsWith("!")) {
                kotlinTypeName.dropLast(1)
            } else {
                kotlinTypeName
            }
        }
    }
}