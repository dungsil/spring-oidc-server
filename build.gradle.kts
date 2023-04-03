plugins {
  kotlin("jvm") version "1.8.10"
  kotlin("plugin.jpa") version "1.8.10"
  kotlin("plugin.spring") version "1.8.10"

  id("org.springframework.boot") version "3.0.5"
  id("io.spring.dependency-management") version "1.1.0"
}

repositories {
  mavenCentral()
}

configurations {
  compileOnly {
    extendsFrom(configurations.annotationProcessor.get())
  }
}

dependencies {
  // Kotlin
  implementation(kotlin("stdlib-jdk8"))
  implementation(kotlin("reflect"))
  testImplementation(kotlin("test-junit5"))

  // Spring boot v3
  fun springBoot(module: String) = "org.springframework.boot:spring-boot-$module"
  fun springBootStarter(module: String) = springBoot("starter-$module")

  developmentOnly(springBoot("devtools"))
  annotationProcessor(springBoot("configuration-processor"))
  implementation(springBootStarter("web"))
  implementation(springBootStarter("data-jpa"))
  implementation(springBootStarter("security"))
  implementation(springBootStarter("oauth2-resource-server"))
  implementation(springBootStarter("validation"))
  implementation(springBootStarter("actuator"))
  testImplementation(springBootStarter("test"))

  // Spring security v6 & Spring security authorization server v1
  implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.0.1")
  testImplementation("org.springframework.security:spring-security-test")

  // Liquibase
  implementation("org.liquibase:liquibase-core")

  // JDBC Driver
  runtimeOnly("org.postgresql:postgresql")

  // .env
  implementation("me.paulschwarz:spring-dotenv:3.0.0")
}

kotlin {
  jvmToolchain(17)
}

tasks {
  compileKotlin {
    kotlinOptions {
      jvmTarget = "17"
      freeCompilerArgs = listOf("-Xjsr305=strict")
    }
  }

  test {
    useJUnitPlatform()
  }
}
