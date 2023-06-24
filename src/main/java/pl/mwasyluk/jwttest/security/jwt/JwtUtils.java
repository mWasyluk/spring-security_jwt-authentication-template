package pl.mwasyluk.jwttest.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.MissingClaimException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class JwtUtils {
    
    private final static long expirationTime = TimeUnit.DAYS.toMillis( 31 );
    private final static List<String> requiredClaims = List.of( "username", "authorities" );
    
    private final Algorithm jwtAlgorithm;
    private final String jwtIssuer;
    
    // provide a basic verification configuration
    private Verification basicVerification() {
        Verification verification = JWT
                .require( jwtAlgorithm )
                .withIssuer( jwtIssuer )
                .acceptExpiresAt( 0 );
        
        for ( String claim : requiredClaims ) {
            verification.withClaimPresence( claim );
        }
        
        return verification;
    }
    
    // retrieve a username from the given token
    public String extractUsername( String token ) {
        DecodedJWT decodedJWT = verifyToken( token );
        
        return decodedJWT.getClaim( "username" ).asString();
    }
    
    // verify the given token
    public DecodedJWT verifyToken( String token ) {
        JWTVerifier jwtVerifier = basicVerification()
                .build();
        
        return jwtVerifier.verify( token );
    }
    
    // generate JWT based on the given claims
    public String generateToken( Map<String, ?> claims ) {
        // ensure that the given claims contain each of the required keys
        if ( !claims.keySet().containsAll( requiredClaims ) ) {
            throw new MissingClaimException( "Cannot generate token without all required claims" );
        }
        
        return JWT.create()
                .withIssuer( jwtIssuer )
                .withPayload( claims )
                .withExpiresAt( Instant.now().plusMillis( expirationTime ) )
                .withIssuedAt( Instant.now() )
                .sign( jwtAlgorithm );
    }
    
    // generate JWT based on the given user details
    public String generateToken( UserDetails userDetails ) {
        // map the user's authorities to a list of strings
        List<String> authorities = userDetails.getAuthorities().stream()
                .map( GrantedAuthority::getAuthority )
                .toList();
        
        return generateToken( Map.of(
                "username", userDetails.getUsername(),
                "authorities", authorities
        ) );
    }
}
