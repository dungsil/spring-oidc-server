package oidc.allinone.global.config

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import oidc.allinone.global.AppEnvironment
import oidc.allinone.global.utils.CryptoUtils
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType.*
import org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST
import org.springframework.security.oauth2.core.oidc.OidcScopes.OPENID
import org.springframework.security.oauth2.core.oidc.OidcScopes.PROFILE
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
class OidcConfig {

  @Bean
  @Order(HIGHEST_PRECEDENCE)
  fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
    // @formatter:off
    return http
      .also { OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(it) }
      .also { it.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java).oidc(withDefaults()) }
      .exceptionHandling{ it.authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login")) }
      .oauth2ResourceServer{ it.jwt() }
      .build()
    // @formatter:on
  }

  // @formatter:off
  @Bean
  fun registeredClientRepository(
    jdbcTemplate: JdbcTemplate,
    passwordEncoder: PasswordEncoder,
    env: AppEnvironment
  ): RegisteredClientRepository {
    val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)

    // Check an init client
    if (registeredClientRepository.findByClientId(env.oauth2ClientId) == null) {
      registeredClientRepository.save(
        RegisteredClient
          .withId(UUID.randomUUID().toString()) // ID
          .clientAuthenticationMethod(CLIENT_SECRET_POST) // 클라이언트 인증 방식
          .clientId(env.oauth2ClientId) // 클라이언트 ID
          .clientSecret(passwordEncoder.encode(env.oauth2ClientSecret)) // 클라이언트 비밀번호
          .authorizationGrantType(AUTHORIZATION_CODE) // 인가 코드
          .authorizationGrantType(REFRESH_TOKEN) // 리프레시 토큰
          .authorizationGrantType(CLIENT_CREDENTIALS) // 클라이언트 내부사용
          .redirectUri(env.publicUrl) // 메인 경로는 기본으로 설정
          .redirectUri(env.publicUrl + "/authorized") // 인증 후 토큰을 발급 받는 경로는 기본적으로 설정
          .redirectUris { it.addAll(env.oauth2RedirectUris) }
          .scope(OPENID)
          .scope(PROFILE)
          .clientSettings(env.oauth2Settings)
          .build()
      )
    }

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
    val keyPair = CryptoUtils.generateRsaKey()
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
