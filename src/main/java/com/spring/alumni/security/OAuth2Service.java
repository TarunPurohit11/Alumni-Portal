package com.spring.alumni.security;

import com.spring.alumni.dtos.LoginResponseDto;
import com.spring.alumni.dtos.SignupRequestDto;
import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.AuthProviderType;
import com.spring.alumni.entities.type.Role;
import com.spring.alumni.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final UserRepository userRepository;
    private final AuthUtil authUtil;

    @Transactional
    public ResponseEntity<LoginResponseDto> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {

        AuthProviderType providerType = authUtil.getProviderTypeFromRegistrationId(registrationId);
        String providerId = authUtil.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        User user = userRepository.findByProviderIdAndProviderType(providerId, providerType).orElse(null);
        String email = oAuth2User.getAttribute("email");
        User emailUser = userRepository.findByUsername(email).orElse(null);

        if (user == null && emailUser == null) {
            String username = authUtil.determineUsernameFromOAuth2User(oAuth2User, registrationId, providerId);
            user = oAuth2Signup(new SignupRequestDto(username, null), providerType, providerId);
        } else if (user != null) {
            if (email != null && !email.isBlank() && !email.equals(user.getUsername())) {
                user.setUsername(email);
                userRepository.save(user);
            }
        } else {
            throw new BadCredentialsException("This email is already registered with provider " + emailUser.getProviderType());
        }

        // FIX: include role
        LoginResponseDto loginResponseDto = new LoginResponseDto(
                authUtil.generateAccessToken(user),
                user.getId(),
                user.getRole().name()
        );

        return ResponseEntity.ok(loginResponseDto);
    }

    public User oAuth2Signup(SignupRequestDto signupRequestDto, AuthProviderType authProviderType, String providerId){
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);
        if(user != null){
            throw new IllegalArgumentException("Username already exists");
        }

        user = userRepository.save(User.builder()
                .username(signupRequestDto.getUsername())
                .providerType(authProviderType)
                .providerId(providerId)
                .build());
        if(authProviderType == AuthProviderType.GOOGLE){
            user.setRole(Role.STUDENT);
        } else if (authProviderType == AuthProviderType.LINKEDIN) {
            user.setRole(Role.ALUMNI);
        }

        return userRepository.save(user);
    }
}
