package com.spring.alumni.services;

import com.spring.alumni.dtos.LoginRequestDto;
import com.spring.alumni.dtos.LoginResponseDto;
import com.spring.alumni.dtos.SignupRequestDto;
import com.spring.alumni.dtos.SignupResponseDto;
import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.AuthProviderType;
import com.spring.alumni.entities.type.Role;
import com.spring.alumni.repositories.UserRepository;
import com.spring.alumni.security.AuthUtil;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final AuthUtil authUtil;
    private final PasswordEncoder passwordEncoder;
    public LoginResponseDto login(LoginRequestDto loginRequestDto){

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword())
        );
        User user = (User) authentication.getPrincipal();
        String token = authUtil.generateAccessToken(user);

        return new LoginResponseDto(token,user.getId());
    }

    public SignupResponseDto signup(SignupRequestDto signupRequestDto){
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);
        if(user != null){
            throw new IllegalArgumentException("Username already exists");
        }

        user = userRepository.save(User.builder()
                .username(signupRequestDto.getUsername())
                .providerType(AuthProviderType.EMAIL)
                .providerId(null)
                        .role(Role.STUDENT)
                .build());

        return new SignupResponseDto(user.getId(),user.getUsername());
    }

}
