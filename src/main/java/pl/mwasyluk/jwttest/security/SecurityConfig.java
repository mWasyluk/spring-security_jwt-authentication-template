package pl.mwasyluk.jwttest.security;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final Filter jwtAuthenticationFilter;
    
    @Bean
    SecurityFilterChain filterChain( HttpSecurity http ) throws Exception {
        http.csrf( AbstractHttpConfigurer::disable );
        http.sessionManagement( cus -> cus.sessionCreationPolicy( SessionCreationPolicy.STATELESS ) );
        http.addFilterBefore( jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class );
        
        http.authorizeHttpRequests( ( auth ) -> auth
                .requestMatchers( "/" ).permitAll()
                .requestMatchers( "/login" ).permitAll()
                .anyRequest().authenticated() );
        
        return http.build();
    }
}
