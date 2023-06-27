package pl.mwasyluk.jwttest.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtConfig {
    
    private final JwtProperties properties;
    
    public Algorithm getHashingAlgorithm() {
        return Algorithm.HMAC256( properties.getSecret() );
    }
}
