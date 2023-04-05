package oidc.allinone.global.utils

import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator

internal object CryptoUtils {
  val passwordEncoder: PasswordEncoder = createDelegatingPasswordEncoder()

  fun generateRsaKey(): KeyPair {
    val keyPair: KeyPair = try {
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
      keyPairGenerator.initialize(2048)
      keyPairGenerator.generateKeyPair()
    } catch (ex: Exception) {
      throw IllegalStateException(ex)
    }
    return keyPair
  }
}
