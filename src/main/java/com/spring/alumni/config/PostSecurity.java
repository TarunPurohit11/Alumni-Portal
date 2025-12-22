package com.spring.alumni.config;

import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.GroupPostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PostSecurity {

    private final GroupPostRepository repo;

    public boolean isOwner(Long postId, User user) {
        return repo.findById(postId)
                .map(post -> post.getCreatedBy().getId().equals(user.getId()))
                .orElse(false);
    }
}
