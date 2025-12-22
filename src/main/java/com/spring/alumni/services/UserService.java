package com.spring.alumni.services;

import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.Role;
import com.spring.alumni.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;


    public Page<User> getAllUsers(int page, int size) {
        Pageable pageable = PageRequest.of(page,size);
        return userRepository.findAll(pageable);
    }

}
