plugins {
    java
    alias(libs.plugins.defaults)
    alias(libs.plugins.license)
}

group = "com.hivemq.extensions.enterprise.security.customizations"
description = "Hello World Customization for the HiveMQ Enterprise Security Extension"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.hivemq.enterpriseSecurityExtension.customizationSdk)
    compileOnly(libs.jetbrains.annotations)
}

tasks {
    compileJava {
        sourceCompatibility = JavaVersion.VERSION_11.toString()
        targetCompatibility = JavaVersion.VERSION_11.toString()
    }
    compileTestJava {
        sourceCompatibility = JavaVersion.VERSION_21.toString()
        targetCompatibility = JavaVersion.VERSION_21.toString()
    }
}

@Suppress("UnstableApiUsage")
testing {
    suites {
        withType<JvmTestSuite> {
            useJUnitJupiter(libs.versions.junit.jupiter)
        }
        "test"(JvmTestSuite::class) {
            dependencies {
                implementation(libs.assertj)
                implementation(libs.hivemq.mqttClient)
                implementation(libs.mockserverNeoLight.client)
                implementation(libs.mockserverNeoLight.testcontainers)
                implementation(libs.shrinkwrap.api)
                runtimeOnly(libs.shrinkwrap.impl)
                implementation(libs.testcontainers.hivemq)
                implementation(libs.testcontainers.junitJupiter)
            }
        }
    }
}

tasks.withType<Jar>().configureEach {
    manifest.attributes(
        "Implementation-Title" to project.name,
        "Implementation-Vendor" to "HiveMQ GmbH",
        "Implementation-Version" to project.version,
    )
}

license {
    header = rootDir.resolve("HEADER")
    mapping("java", "SLASHSTAR_STYLE")
}
