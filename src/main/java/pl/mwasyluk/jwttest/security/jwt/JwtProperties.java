package pl.mwasyluk.jwttest.security.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties( prefix = "security.jwt" )
public class JwtProperties {
    
    private String issuer;
    private String secret;
    private String cookieName;
}
