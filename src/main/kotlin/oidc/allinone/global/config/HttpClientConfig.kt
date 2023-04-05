package oidc.allinone.global.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.client.RestTemplate

/**
 *
 * @author 김용건 &lt;jonathan@lsware.com&gt;
 * @since 2023.04.05
 */
@Configuration
class HttpClientConfig {

  @Bean
  fun httpClient(): RestTemplate = RestTemplate()
}
