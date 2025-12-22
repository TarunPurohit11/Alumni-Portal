package com.spring.alumni.controllers;

import com.spring.alumni.dtos.LoginRequestDto;
import com.spring.alumni.dtos.LoginResponseDto;
import com.spring.alumni.dtos.SignupRequestDto;
import com.spring.alumni.dtos.SignupResponseDto;
import com.spring.alumni.services.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto){
        return ResponseEntity.ok(authService.login(loginRequestDto));
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(@RequestBody SignupRequestDto signupRequestDto){
        return ResponseEntity.ok(authService.signup(signupRequestDto));
    }

    @GetMapping("/auth/clear")
    public ResponseEntity<String> clearOAuth2(HttpServletRequest request) {
        request.getSession().removeAttribute(
                HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST"
        );
        return ResponseEntity.ok("cleared");
    }

}
