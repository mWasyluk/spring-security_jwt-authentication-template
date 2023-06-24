package pl.mwasyluk.jwttest.models;

import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class AuthenticationDetails {
    
    @NotEmpty
    private String username;
    @NotEmpty
    private String password;
}
