package fr.salaun.tristan.reflexionforfrida

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TypeMapperTest {

    // --- convertTypeFromKotlinToFrida ---

    @Test
    fun `convert ByteArray to JVM type`() {
        assertEquals("[B", TypeMapper.convertTypeFromKotlinToFrida("kotlin.ByteArray"))
        assertEquals("[B", TypeMapper.convertTypeFromKotlinToFrida("kotlin.ByteArray!"))
    }

    @Test
    fun `convert primitive types`() {
        assertEquals("int", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Int"))
        assertEquals("int", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Int!"))
        assertEquals("long", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Long"))
        assertEquals("short", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Short"))
        assertEquals("byte", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Byte"))
        assertEquals("float", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Float"))
        assertEquals("double", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Double"))
        assertEquals("boolean", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Boolean"))
        assertEquals("char", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Char"))
    }

    @Test
    fun `convert String types`() {
        assertEquals("java.lang.String", TypeMapper.convertTypeFromKotlinToFrida("kotlin.String"))
        assertEquals("java.lang.String", TypeMapper.convertTypeFromKotlinToFrida("kotlin.String!"))
    }

    @Test
    fun `convert boxed array types`() {
        assertEquals("[Ljava.lang.Integer;", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Array<kotlin.Int>"))
        assertEquals("[Ljava.lang.String;", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Array<kotlin.String>"))
        assertEquals("[Ljava.lang.Boolean;", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Array<kotlin.Boolean>"))
        assertEquals("[Ljava.lang.Byte;", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Array<kotlin.Byte>"))
    }

    @Test
    fun `convert primitive array types`() {
        assertEquals("[Z", TypeMapper.convertTypeFromKotlinToFrida("kotlin.BooleanArray"))
        assertEquals("[C", TypeMapper.convertTypeFromKotlinToFrida("kotlin.CharArray"))
        assertEquals("[D", TypeMapper.convertTypeFromKotlinToFrida("kotlin.DoubleArray"))
        assertEquals("[F", TypeMapper.convertTypeFromKotlinToFrida("kotlin.FloatArray"))
        assertEquals("[I", TypeMapper.convertTypeFromKotlinToFrida("kotlin.IntArray"))
        assertEquals("[J", TypeMapper.convertTypeFromKotlinToFrida("kotlin.LongArray"))
        assertEquals("[S", TypeMapper.convertTypeFromKotlinToFrida("kotlin.ShortArray"))
    }

    @Test
    fun `convert unsigned types`() {
        assertEquals("byte", TypeMapper.convertTypeFromKotlinToFrida("kotlin.UByte"))
        assertEquals("int", TypeMapper.convertTypeFromKotlinToFrida("kotlin.UInt"))
        assertEquals("long", TypeMapper.convertTypeFromKotlinToFrida("kotlin.ULong"))
        assertEquals("short", TypeMapper.convertTypeFromKotlinToFrida("kotlin.UShort"))
    }

    @Test
    fun `convert Any nullable to Object`() {
        assertEquals("java.lang.Object", TypeMapper.convertTypeFromKotlinToFrida("kotlin.Any?"))
    }

    @Test
    fun `platform types strip exclamation mark`() {
        assertEquals("javax.crypto.Cipher", TypeMapper.convertTypeFromKotlinToFrida("javax.crypto.Cipher!"))
        assertEquals("java.security.Key", TypeMapper.convertTypeFromKotlinToFrida("java.security.Key!"))
    }

    @Test
    fun `unknown types pass through unchanged`() {
        assertEquals("javax.crypto.Cipher", TypeMapper.convertTypeFromKotlinToFrida("javax.crypto.Cipher"))
        assertEquals("java.security.Key", TypeMapper.convertTypeFromKotlinToFrida("java.security.Key"))
    }

    // --- compareTypes ---

    @Test
    fun `identical types match`() {
        assertTrue(TypeMapper.compareTypes("String", "String"))
        assertTrue(TypeMapper.compareTypes("int", "int"))
    }

    @Test
    fun `documentation primitives match Kotlin types`() {
        assertTrue(TypeMapper.compareTypes("int", "Int"))
        assertTrue(TypeMapper.compareTypes("byte", "Byte"))
        assertTrue(TypeMapper.compareTypes("long", "Long"))
        assertTrue(TypeMapper.compareTypes("short", "Short"))
        assertTrue(TypeMapper.compareTypes("float", "Float"))
        assertTrue(TypeMapper.compareTypes("double", "Double"))
        assertTrue(TypeMapper.compareTypes("boolean", "Boolean"))
        assertTrue(TypeMapper.compareTypes("char", "Char"))
    }

    @Test
    fun `byte array matches ByteArray and ByteBuffer`() {
        assertTrue(TypeMapper.compareTypes("byte[]", "ByteArray"))
        assertTrue(TypeMapper.compareTypes("byte[]", "ByteBuffer"))
    }

    @Test
    fun `non-matching types return false`() {
        assertFalse(TypeMapper.compareTypes("int", "String"))
        assertFalse(TypeMapper.compareTypes("byte", "Int"))
        assertFalse(TypeMapper.compareTypes("UnknownDoc", "UnknownReflect"))
    }

    // --- getSimpleTypeName ---

    @Test
    fun `fully qualified name returns simple name`() {
        assertEquals("Cipher", TypeMapper.getSimpleTypeName("javax.crypto.Cipher"))
        assertEquals("Key", TypeMapper.getSimpleTypeName("java.security.Key"))
        assertEquals("String", TypeMapper.getSimpleTypeName("java.lang.String"))
    }

    @Test
    fun `simple name returns unchanged`() {
        assertEquals("int", TypeMapper.getSimpleTypeName("int"))
        assertEquals("ByteArray", TypeMapper.getSimpleTypeName("ByteArray"))
    }

    @Test
    fun `nullable type cleans non-alphanumeric`() {
        assertEquals("Any", TypeMapper.getSimpleTypeName("kotlin.Any?"))
    }
}
