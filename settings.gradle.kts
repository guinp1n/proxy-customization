rootProject.name = "hivemq-enterprise-security-hello-world-customization"

if (file("../hivemq-enterprise-security-extension-customization-sdk").exists()) {
    includeBuild("../hivemq-enterprise-security-extension-customization-sdk")
}
