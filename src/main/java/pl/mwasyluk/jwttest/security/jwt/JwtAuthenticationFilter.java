package pl.mwasyluk.jwttest.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Log4j2
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain filterChain ) throws ServletException, IOException {
        // get the authorization header from the request and validate it
        String header = request.getHeader( HttpHeaders.AUTHORIZATION );
        if ( header == null || !header.startsWith( "Bearer " ) ) {
            filterChain.doFilter( request, response );
            return;
        }
        
        // retrieve a JWT from the header
        String tokenString = header.split( " " )[1];
        if ( tokenString.isEmpty() ) {
            filterChain.doFilter( request, response );
            return;
        }
        
        // verify the retrieved JWT and find the user by their username
        String username = jwtUtils.extractUsername( tokenString );
        UserDetails userDetails = userDetailsService.loadUserByUsername( username );
        
        // create the authentication token and pass it to the security context
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(),
                userDetails.getPassword(),
                userDetails.getAuthorities()
        );
        token.setDetails( new WebAuthenticationDetailsSource().buildDetails( request ) );
        SecurityContextHolder.getContext().setAuthentication( token );
        
        // continue filtering
        filterChain.doFilter( request, response );
    }
    
}
