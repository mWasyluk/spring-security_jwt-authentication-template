package pl.mwasyluk.jwttest.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint(){
        return ResponseEntity.ok("Welcome to the public endpoint");
    }
    
    @GetMapping("/private")
    public ResponseEntity<String> privateEndpoint(){
        return ResponseEntity.ok("Welcome to the private endpoint");
    }
}
