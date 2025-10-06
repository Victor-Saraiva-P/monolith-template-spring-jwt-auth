package com.victorsaraiva.auth_base_jwt.configs;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

  @Value("${security.frontend-url}")
  private String FRONTEND_URL;

  @Value("${api.base-url}")
  private String API_BASE_URL;

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry
        .addMapping(API_BASE_URL + "/**")
        .allowedOrigins(FRONTEND_URL)
        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
        .allowedHeaders("*")
        .allowCredentials(true);
  }
}
