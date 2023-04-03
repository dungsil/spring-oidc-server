package oidc.allinone.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.03.31
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
class SecurityConfig {
  @Bean
  fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
}
