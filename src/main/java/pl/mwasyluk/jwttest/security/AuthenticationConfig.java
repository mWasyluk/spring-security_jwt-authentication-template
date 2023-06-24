package pl.mwasyluk.jwttest.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@RequiredArgsConstructor
public class AuthenticationConfig {
    
    @Bean
    UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        
        manager.createUser( User.builder()
                .username( "admin" )
                .password( passwordEncoder().encode( "pass" ) )
                .authorities( "ADMIN", "USER" )
                .build() );
        manager.createUser( User.builder()
                .username( "user" )
                .password( passwordEncoder().encode( "pass" ) )
                .authorities( "USER" )
                .build() );
        
        return manager;
    }
    
    
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder( 12 );
    }
    
    @Bean
    AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider( passwordEncoder() );
        daoAuthenticationProvider.setUserDetailsService( userDetailsService() );
        return new ProviderManager( daoAuthenticationProvider );
    }
}
