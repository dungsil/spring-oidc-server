package oidc.allinone.global.env

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Component

@Component
class OAuth2Environment(
  @Value("\${APP_OAUTH2_CLIENT_ID}")
  val clientId: String,

  @Value("\${APP_OAUTH2_CLIENT_SECRET}")
  val clientSecret: String,

  @Value("\${APP_OAUTH2_CLIENT_REDIRECT_URI}")
  val redirectUri: String,
) {
  val redirectUris: List<String> = this.redirectUri.split(",").map { it.trimIndent() }
  val settings: ClientSettings = createSettings()

  private fun createSettings(): ClientSettings {
    return ClientSettings.builder()
      .requireAuthorizationConsent(true)
      .build()
  }
}
