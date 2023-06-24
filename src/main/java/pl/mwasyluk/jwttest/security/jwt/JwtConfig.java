package pl.mwasyluk.jwttest.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtConfig {
    
    @Value( "${security.jwt.issuer}" )
    private String issuer;
    
    @Value( "${security.jwt.secret}" )
    private String secret;
    
    @Bean
    String jwtIssuer() {
        return issuer;
    }
    
    @Bean
    Algorithm jwtAlgorithm() {
        return Algorithm.HMAC256( secret );
    }
}
