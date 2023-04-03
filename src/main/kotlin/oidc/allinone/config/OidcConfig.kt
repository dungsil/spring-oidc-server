package oidc.allinone.config

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import oidc.allinone.utils.KeyGeneratorUtils
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.03.31
 */
@Configuration
class OidcConfig(@Value("\${APP_PUBLIC_URL}") private val appPublicUrl: String) {

  @Bean
  @Order(HIGHEST_PRECEDENCE)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
    http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
      .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0

    // @formatter:off
    http
      .exceptionHandling{exceptions:ExceptionHandlingConfigurer<HttpSecurity?> -> exceptions.authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login"))}
      .oauth2ResourceServer{obj:OAuth2ResourceServerConfigurer<HttpSecurity?> -> obj.jwt()}
    // @formatter:on
    return http.build()
  }

  // @formatter:off
  @Bean fun registeredClientRepository(jdbcTemplate:JdbcTemplate): RegisteredClientRepository? {
    val registeredClient: RegisteredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("messaging-client")
      .clientSecret("{noop}secret")
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
      .redirectUri("$appPublicUrl/login/oauth2/code/messaging-client-oidc")
      .redirectUri("$appPublicUrl/authorized")
      .scope(OidcScopes.OPENID)
      .scope(OidcScopes.PROFILE)
      .scope("message.read")
      .scope("message.write")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .build()

    // Save registered client in db as if in-memory
    val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)
    registeredClientRepository.save(registeredClient)
    return registeredClientRepository
  }
  // @formatter:on

  // @formatter:on
  @Bean
  fun authorizationService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository
  ): OAuth2AuthorizationService {
    return JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun authorizationConsentService(
    jdbcTemplate: JdbcTemplate,
    registeredClientRepository: RegisteredClientRepository
  ): OAuth2AuthorizationConsentService {
    return JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)
  }

  @Bean
  fun jwkSource(): JWKSource<SecurityContext?> {
    val rsaKey: RSAKey = generateRsa()
    val jwkSet = JWKSet(rsaKey)
    return JWKSource<SecurityContext?> { jwkSelector: JWKSelector, _: SecurityContext? ->
      jwkSelector.select(
        jwkSet
      )
    }
  }

  @Bean
  fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>): JwtDecoder {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
  }

  @Bean
  fun authorizationServerSettings(): AuthorizationServerSettings {
    return AuthorizationServerSettings.builder().build()
  }


  private fun generateRsa(): RSAKey {
    val keyPair = KeyGeneratorUtils.generateRsaKey()
    val publicKey = keyPair.public as RSAPublicKey
    val privateKey = keyPair.private as RSAPrivateKey

    // @formatter:off
    return RSAKey.Builder(publicKey)
      .privateKey(privateKey)
      .keyID(UUID.randomUUID().toString())
      .build()
    // @formatter:on
  }
}
