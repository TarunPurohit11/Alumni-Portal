package com.spring.alumni.services;

import com.spring.alumni.dtos.GroupPostDTO;
import com.spring.alumni.entities.Group;
import com.spring.alumni.entities.GroupPost;
import com.spring.alumni.entities.User;
import com.spring.alumni.repositories.GroupPostRepository;
import com.spring.alumni.repositories.GroupRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GroupPostService {

    private final GroupPostRepository groupPostRepository;
    private final GroupRepository groupRepository;

    /* ================= FETCH POSTS ================= */
    // GroupPostService.java (simplified)
    public List<GroupPostDTO> getGroupPosts(Long groupId, User user) {
        List<GroupPost> posts = groupPostRepository.findByGroupId(groupId);
        return posts.stream().map(post -> new GroupPostDTO(
                post.getId(),
                post.getTitle(),
                post.getContent(),
                post.getCreatedBy().getName(),
                post.getCreatedBy().getId(),
                post.getCreatedBy().getId().equals(user.getId()), // ownPost
                post.getCreatedAt()
        )).collect(Collectors.toList());
    }


    /* ================= CREATE POST ================= */
    public void createPost(Long groupId, String title, String content, User user) {

        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new RuntimeException("Group not found"));

        GroupPost post = GroupPost.builder()
                .title(title)
                .content(content)
                .group(group)
                .createdBy(user)
                .createdAt(LocalDateTime.now())
                .build();

        groupPostRepository.save(post);
    }


    /* ================= DELETE POST ================= */
    public void deletePost(Long postId) {
        if (!groupPostRepository.existsById(postId)) {
            throw new RuntimeException("Post not found");
        }
        groupPostRepository.deleteById(postId);
    }
}
