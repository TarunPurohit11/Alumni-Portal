package com.spring.alumni.services;

import com.spring.alumni.dtos.AdminActionResponseDTO;
import com.spring.alumni.dtos.AdminUserResponseDTO;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminService {

    private final UserRepository userRepository;


    @Transactional
    public AdminActionResponseDTO toggleUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setEnabled(!user.isEnabled());

        User saved = userRepository.save(user);

        String msg = saved.isEnabled()
                ? "User enabled successfully"
                : "User disabled successfully";

        return AdminActionResponseDTO.builder()
                .success(true)
                .message(msg)
                .user(mapToDto(saved))
                .build();
    }


    @Transactional
    public AdminActionResponseDTO deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        userRepository.delete(user);

        return AdminActionResponseDTO.builder()
                .success(true)
                .message("User deleted successfully")
                .user(mapToDto(user)) // last snapshot
                .build();
    }

    private AdminUserResponseDTO mapToDto(User user) {
        return AdminUserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .name(user.getName())
                .profilePic(user.getProfilePic())
                .title(user.getTitle())
                .company(user.getCompany())
                .course(user.getCourse())
                .year(user.getYear())
                .city(user.getCity())
                .about(user.getAbout())
                .skills(user.getSkills())
                .build();
    }

    public Page<AdminUserResponseDTO> getAllUsers(int page, int size) {

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by("id").descending()
        );

        return userRepository.findAll(pageable)
                .map(this::mapToDto);
    }

}

