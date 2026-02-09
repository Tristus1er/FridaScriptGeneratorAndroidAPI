package fr.salaun.tristan.reflexionforfrida

/**
 * Handles type conversions between Kotlin reflection types, Android documentation types,
 * and Frida hook types.
 */
object TypeMapper {

    /**
     * Mapping from Android documentation types to their Kotlin reflection equivalents.
     * Used to match documentation entries with reflected methods.
     */
    private val docTypeToReflectedTypes = mapOf(
        // Primitives
        "byte" to setOf("Byte"),
        "short" to setOf("Short"),
        "int" to setOf("Int"),
        "long" to setOf("Long"),
        "float" to setOf("Float"),
        "double" to setOf("Double"),
        "boolean" to setOf("Boolean"),
        "char" to setOf("Char"),
        // Primitive arrays
        "byte[]" to setOf("ByteArray", "ByteBuffer"),
        "short[]" to setOf("ShortArray"),
        "int[]" to setOf("IntArray"),
        "long[]" to setOf("LongArray"),
        "float[]" to setOf("FloatArray"),
        "double[]" to setOf("DoubleArray"),
        "boolean[]" to setOf("BooleanArray"),
        "char[]" to setOf("CharArray"),
        // Common object types
        "String" to setOf("String"),
        "Object" to setOf("Any", "Any?"),
    )

    /**
     * Compare a documentation type with a reflected type.
     * Returns true if they represent the same type.
     */
    fun compareTypes(docType: String, reflectedType: String): Boolean {
        if (docType == reflectedType) return true
        return docTypeToReflectedTypes[docType]?.contains(reflectedType) == true
    }

    /**
     * Extract the simple type name from a fully qualified name.
     * e.g., "java.security.Key" -> "Key"
     */
    fun getSimpleTypeName(rawName: String): String {
        return if (rawName.contains('.')) {
            rawName.substringAfterLast('.').replace("[^A-Za-z0-9 ]".toRegex(), "")
        } else {
            rawName
        }
    }

    /**
     * Convert a Kotlin reflection type name to its Frida/JVM equivalent.
     */
    fun convertTypeFromKotlinToFrida(kotlinTypeName: String): String {
        return when (kotlinTypeName) {
            "kotlin.ByteArray", "kotlin.ByteArray!" -> "[B"

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
            "kotlin.Int", "kotlin.Int!" -> "int"
            "kotlin.Long" -> "long"
            "kotlin.Short" -> "short"
            "kotlin.String", "kotlin.String!" -> "java.lang.String"

            "kotlin.UByte" -> "byte"
            "kotlin.UInt" -> "int"
            "kotlin.ULong" -> "long"
            "kotlin.UShort" -> "short"

            "kotlin.BooleanArray" -> "[Z"
            "kotlin.CharArray" -> "[C"
            "kotlin.DoubleArray" -> "[D"
            "kotlin.FloatArray" -> "[F"
            "kotlin.IntArray" -> "[I"
            "kotlin.LongArray" -> "[J"
            "kotlin.ShortArray" -> "[S"

            "kotlin.ULongArray" -> "[Lkotlin.ULong;"
            "kotlin.UShortArray" -> "[Lkotlin.UShort;"
            "kotlin.UByteArray" -> "[Lkotlin.UByte;"
            "kotlin.UIntArray" -> "[Lkotlin.UInt;"

            "kotlin.Any?" -> "java.lang.Object"

            else -> if (kotlinTypeName.endsWith("!")) {
                kotlinTypeName.dropLast(1)
            } else {
                kotlinTypeName
            }
        }
    }
}
