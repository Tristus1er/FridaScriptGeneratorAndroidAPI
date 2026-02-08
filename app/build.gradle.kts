plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "fr.salaun.tristan.reflexionforfrida"
    compileSdk = 34

    defaultConfig {
        applicationId = "fr.salaun.tristan.reflexionforfrida"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")

    // Code generator templating
    // https://mvnrepository.com/artifact/org.freemarker/freemarker-gae
    implementation("org.freemarker:freemarker-gae:2.3.33")

    // Error: java.lang.NoClassDefFoundError: Failed resolution of: Ljava/beans/Introspector;
    // https://mvnrepository.com/artifact/me.champeau.openbeans/openbeans
    implementation("me.champeau.openbeans:openbeans:1.0.2")


    // For reflexion
    implementation("org.jetbrains.kotlin:kotlin-reflect:1.9.22")

    // Parsing HTML
    // https://mvnrepository.com/artifact/org.jsoup/jsoup
    implementation("org.jsoup:jsoup:1.18.1")
}