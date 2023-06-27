package pl.mwasyluk.jwttest.controllers;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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
    public ResponseEntity<String> login( @RequestBody @Valid AuthenticationDetails authenticationDetails, HttpServletResponse response ) {
        // authenticate user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationDetails.getUsername(),
                        authenticationDetails.getPassword() ) );
        
        // retrieve user details from the authentication
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        
        // append authentication cookie
        jwtUtils.appendJwtCookieToResponse( response, jwtUtils.generateToken( userDetails ) );
        return ResponseEntity.ok( "Hello, " + userDetails.getUsername() + "!" );
    }
}
