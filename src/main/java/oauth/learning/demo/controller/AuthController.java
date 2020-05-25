package oauth.learning.demo.controller;

import oauth.learning.demo.exception.BadRequestException;
import oauth.learning.demo.model.AuthProvider;
import oauth.learning.demo.model.User;
import oauth.learning.demo.payload.ApiResponse;
import oauth.learning.demo.payload.AuthResponse;
import oauth.learning.demo.payload.LoginRequest;
import oauth.learning.demo.payload.SignUpRequest;
import oauth.learning.demo.repository.UserRepository;
import oauth.learning.demo.security.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private AuthenticationManager authenticationManager;
  private UserRepository userRepository;
  private PasswordEncoder passwordEncoder;
  private TokenProvider tokenProvider;

  @Autowired
  public AuthController(
          AuthenticationManager authenticationManager,
          UserRepository userRepository,
          PasswordEncoder passwordEncoder, TokenProvider tokenProvider) {
    this.authenticationManager = authenticationManager;
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
    this.tokenProvider = tokenProvider;
  }

  @PostMapping("/login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(),
                    loginRequest.getPassword()
            )
    );

    SecurityContextHolder.getContext().setAuthentication(authentication);

    String token = tokenProvider.createToken(authentication);
    return ResponseEntity.ok(new AuthResponse(token));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      throw new BadRequestException("Email address already in use.");
    }

    // Creating user's account
    User user = new User();
    user.setName(signUpRequest.getName());
    user.setEmail(signUpRequest.getEmail());
    user.setPassword(signUpRequest.getPassword());
    user.setProvider(AuthProvider.local);

    user.setPassword(passwordEncoder.encode(user.getPassword()));

    User result = userRepository.save(user);

    URI location = ServletUriComponentsBuilder
            .fromCurrentContextPath().path("/user/me")
            .buildAndExpand(result.getId()).toUri();

    return ResponseEntity.created(location)
            .body(new ApiResponse(true, "User registered successfully@"));
  }

}