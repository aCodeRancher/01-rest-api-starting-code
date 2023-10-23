package com.in28minutes.rest.webservices.restfulwebservices.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(
                    auth -> auth.anyRequest().authenticated())
                    .httpBasic(Customizer.withDefaults())
                   .cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource( request -> {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
                        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
                        configuration.setAllowedHeaders(List.of("*"));
                        return configuration;
                    }))
                    .sessionManagement(
                               session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .csrf(csrf->csrf.disable());
  return http.build();
    }
}
