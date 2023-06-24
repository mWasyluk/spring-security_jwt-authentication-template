package pl.mwasyluk.jwttest.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import pl.mwasyluk.jwttest.models.AuthenticationDetails;
import pl.mwasyluk.jwttest.security.jwt.JwtUtils;

@RestController
@RequiredArgsConstructor
public class LoginController {
    
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    
    @PostMapping( "/login" )
    public ResponseEntity<String> login( @RequestBody @Valid AuthenticationDetails authenticationDetails ) {
        // authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationDetails.getUsername(),
                        authenticationDetails.getPassword() ) );
        
        // retrieve user details from the authentication
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        // return a JWT within the Authorization header
        return ResponseEntity
                .status( HttpStatus.OK )
                .header( HttpHeaders.AUTHORIZATION, "Bearer " + jwtUtils.generateToken( userDetails ) )
                .body( "Hello, " + userDetails.getUsername() + "!" );
    }
}
