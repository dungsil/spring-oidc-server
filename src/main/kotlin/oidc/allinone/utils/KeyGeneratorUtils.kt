package oidc.allinone.utils

import java.security.KeyPair
import java.security.KeyPairGenerator

internal object KeyGeneratorUtils {

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
