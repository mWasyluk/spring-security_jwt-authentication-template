package pl.mwasyluk.jwttest.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {
    
    @GetMapping( "/" )
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok( "Welcome to the public endpoint!" );
    }
    
    @GetMapping( "/secured" )
    public ResponseEntity<String> securedEndpoint( Principal principal ) {
        return ResponseEntity.ok( "Welcome to the secured endpoint, " + principal.getName() + "!" );
    }
}
