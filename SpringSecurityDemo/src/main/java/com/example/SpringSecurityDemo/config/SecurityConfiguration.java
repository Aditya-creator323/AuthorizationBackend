package com.example.SpringSecurityDemo.config;

import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @SuppressWarnings("removal")
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // http
        //     .csrf(AbstractHttpConfigurer::disable)
        //     .authorizeHttpRequests()
        //     .requestMatchers("")
        //     .permitAll()
        //     .anyRequest()
        //     .authenticated()
        //     .and()
        //     .sessionManagement(session -> session
        //             .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        //     )
        //     .and()
        //     .authenticationProvider(authenticationProvider)
        //     .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        http
            .cors()
            .and()
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(
                req->req.requestMatchers("/api/v1/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
            )
            .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsFilter corsFilter() {
        // Create a new CorsConfiguration instance
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowCredentials(true);
        corsConfig.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",
            "https://authorization-react-spring.vercel.app"
        ));
        // corsConfig.addAllowedOrigin("http://localhost:3000"); // Allow requests from your React app
        corsConfig.addAllowedHeader("*"); // Allow all headers
        corsConfig.addAllowedMethod("*"); // Allow all methods (GET, POST, etc.)

        // Map the configuration to a specific path
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig); // Apply to all paths

        // Return the CorsFilter bean
        return new CorsFilter(source);
    }
}
