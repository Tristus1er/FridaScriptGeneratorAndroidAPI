package fr.salaun.tristan.reflexionforfrida

class TestClass {

    fun simpleParam(byteValue: Byte) {}
    fun simpleParam(shortValue: Short) {}
    fun simpleParam(intValue: Int) {}
    fun simpleParam(longValue: Long) {}
    fun simpleParam(floatValue: Float) {}
    fun simpleParam(doubleValue: Double) {}

//    fun simpleParamUByte(ubyteValue: UByte) {}
//    fun simpleParamUShort(ushortValue: UShort) {}
//    fun simpleParamUInt(uintValue: UInt) {}
//    fun simpleParamULong(ulongValue: ULong) {}

    //UByteArray: an array of unsigned bytes.
    //UShortArray: an array of unsigned shorts.
    //UIntArray: an array of unsigned ints.
    //ULongArray: an array of unsigned longs.

    // BooleanArray
    //ByteArray
    //CharArray
    //DoubleArray
    //FloatArray
    //IntArray
    //LongArray
    //ShortArray


    fun simpleParam(booleanValue: Boolean) {}
    fun simpleParam(charValue: Char) {}
    fun simpleParam(stringValue: String) {}

    fun simpleParamArrayOfByte(arrayOfByteValue: Array<Byte>) {}
    fun simpleParam(arrayOfShortValue: Array<Short>) {}
    fun simpleParam(arrayOfIntValue: Array<Int>) {}
    fun simpleParam(arrayOfLongValue: Array<Long>) {}
    fun simpleParam(arrayOfFloatValue: Array<Float>) {}
    fun simpleParam(arrayOfDoubleValue: Array<Double>) {}
    fun simpleParam(arrayOfUByteValue: Array<UByte>) {}
    fun simpleParam(arrayOfUShortValue: Array<UShort>) {}
    fun simpleParam(arrayOfUIntValue: Array<UInt>) {}
    fun simpleParam(arrayOfULongValue: Array<ULong>) {}

    fun simpleParam(arrayOfBooleanValue: Array<Boolean>) {}
    fun simpleParam(arrayOfCharValue: Array<Char>) {}
    fun simpleParam(arrayOfStringValue: Array<String>) {}

    fun simpleParamByteArray(byteArrayOf: ByteArray) {}
    fun simpleParam(shortArrayOf: ShortArray) {}
    fun simpleParam(intArrayOf: IntArray) {}
    fun simpleParam(longArrayOf: LongArray) {}
    fun simpleParam(floatArrayOf: FloatArray) {}
    fun simpleParam(doubleArrayOf: DoubleArray) {}
    @OptIn(ExperimentalUnsignedTypes::class)
    fun simpleParam(ubyteArrayOf: UByteArray) {}
    @OptIn(ExperimentalUnsignedTypes::class)
    fun simpleParam(ushortArrayOf: UShortArray) {}
    @OptIn(ExperimentalUnsignedTypes::class)
    fun simpleParam(uintArrayOf: UIntArray) {}
    @OptIn(ExperimentalUnsignedTypes::class)
    fun simpleParam(ulongArrayOf: ULongArray) {}
    fun simpleParam(booleanArrayOf: BooleanArray) {}
    fun simpleParam(charArrayOf: CharArray) {}
//    private fun simpleParam(stringArrayOf: StringArray) {}

    companion object {
        @OptIn(ExperimentalUnsignedTypes::class)
        fun callAllMethods() {
            val tc = TestClass()
            tc.simpleParam(10.toByte())
            tc.simpleParam(20.toShort())
            tc.simpleParam(30)
            tc.simpleParam(40.toLong())
            tc.simpleParam(50.toFloat())
            tc.simpleParam(60.toDouble())

//            tc.simpleParamUByte(70.toUByte())
//            tc.simpleParamUShort(80.toUShort())
//            tc.simpleParamUInt(90.toUInt())
//            tc.simpleParamULong(100.toULong())


            tc.simpleParam(true)
            tc.simpleParam('c')
            tc.simpleParam("String")
            tc.simpleParamByteArray(byteArrayOf(10.toByte(), 10.toByte()))
            tc.simpleParam(shortArrayOf(20.toShort(), 20.toShort()))
            tc.simpleParam(intArrayOf(30, 30))
            tc.simpleParam(longArrayOf(40.toLong(), 40.toLong()))
            tc.simpleParam(floatArrayOf(50.toFloat(), 50.toFloat()))
            tc.simpleParam(doubleArrayOf(60.toDouble(), 60.toDouble()))
            tc.simpleParam(ubyteArrayOf(70.toUByte(), 70.toUByte()))
            tc.simpleParam(ushortArrayOf(80.toUShort(), 80.toUShort()))
            tc.simpleParam(uintArrayOf(90.toUInt(), 90.toUInt()))
            tc.simpleParam(ulongArrayOf(100.toULong(), 100.toULong()))
            tc.simpleParam(booleanArrayOf(true, false, true))
            tc.simpleParam(charArrayOf('c', 'h'))
            tc.simpleParam(arrayOf("String array"))
            tc.simpleParamArrayOfByte(arrayOf(11.toByte(), 11.toByte()))
            tc.simpleParam(arrayOf(21.toShort(), 21.toShort()))
            tc.simpleParam(arrayOf(31.toInt(), 31.toInt()))
            tc.simpleParam(arrayOf(41.toLong(), 41.toLong()))
            tc.simpleParam(arrayOf(51.toFloat(), 51.toFloat()))
            tc.simpleParam(arrayOf(61.toDouble(), 61.toDouble()))
        }
    }
}