package oidc.allinone.global

import org.springframework.beans.factory.annotation.Value
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.stereotype.Component

@Component
class AppEnvironment(
  @Value("\${APP_PUBLIC_URL:http://localhost:\${server.port:8080}}")
  val publicUrl: String,

  @Value("\${APP_OAUTH2_CLIENT_ID}")
  val oauth2ClientId: String,

  @Value("\${APP_OAUTH2_CLIENT_SECRET}")
  val oauth2ClientSecret: String,

  @Value("\${APP_OAUTH2_CLIENT_REDIRECT_URI:}")
  val oauth2RedirectUri: String,
) {
  val oauth2RedirectUris: List<String> = this.oauth2RedirectUri.split(",").map { it.trimIndent() }
  val oauth2Settings: ClientSettings = createSettings()

  private fun createSettings(): ClientSettings {
    return ClientSettings.builder()
      .requireAuthorizationConsent(false)
      .build()
  }
}
