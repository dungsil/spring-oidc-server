package oidc.allinone.global.config

import oidc.allinone.global.utils.CryptoUtils
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.session.HttpSessionEventPublisher


/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.03.31
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
class SecurityConfig {
  @Bean
  fun passwordEncoder(): PasswordEncoder = CryptoUtils.passwordEncoder

  @Bean
  fun sessionRegistry(): SessionRegistry = SessionRegistryImpl()

  @Bean
  fun httpSessionEventPublisher(): HttpSessionEventPublisher= HttpSessionEventPublisher()

  @Bean
  fun apiSecurityFilterChain(http: HttpSecurity): DefaultSecurityFilterChain {
    // @formatter:off
    return http
      .authorizeHttpRequests { it.anyRequest().authenticated() }
      .formLogin(withDefaults())
      .build()
    // @formatter:on
  }
}
