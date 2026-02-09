# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Keep line number information for debugging stack traces.
-keepattributes SourceFile,LineNumberTable

# Kotlin Reflect - needed for reflection-based analysis
-keep class kotlin.reflect.** { *; }
-keep class kotlin.Metadata { *; }
-keepattributes RuntimeVisibleAnnotations
-keepattributes *Annotation*

# Keep data model classes used by FreeMarker templates
-keep class fr.salaun.tristan.reflexionforfrida.model.** { *; }

# FreeMarker template engine
-keep class freemarker.** { *; }
-dontwarn freemarker.**

# OpenBeans (java.beans replacement for Android)
-keep class me.champeau.openbeans.** { *; }
-dontwarn me.champeau.openbeans.**

# JSoup HTML parser
-keep class org.jsoup.** { *; }
-dontwarn org.jsoup.**
