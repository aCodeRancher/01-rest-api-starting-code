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
//add security config
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.authorizeHttpRequests(
                 auth -> auth.anyRequest().authenticated());
                   http.httpBasic(Customizer.withDefaults());
                   http.cors(httpSecurityCorsConfigurer -> httpSecurityCorsConfigurer.configurationSource( request -> {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
                        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
                        configuration.setAllowedHeaders(List.of("*"));
                        return configuration;
                    }));
                   http.sessionManagement(
                             session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
                   http.csrf(csrf->csrf.disable());
  return http.build();
    }
}
