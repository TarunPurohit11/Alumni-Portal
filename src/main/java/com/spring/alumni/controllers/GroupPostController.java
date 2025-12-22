package com.spring.alumni.controllers;

import com.spring.alumni.dtos.GroupPostDTO;
import com.spring.alumni.entities.User;
import com.spring.alumni.services.GroupPostService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/groups")
@RequiredArgsConstructor
public class GroupPostController {

    private final GroupPostService postService;

    /* ===== GET POSTS ===== */
    @GetMapping("/{groupId}/posts")
    public List<GroupPostDTO> getPosts(@PathVariable Long groupId,
                                       @AuthenticationPrincipal User user) {
        return postService.getGroupPosts(groupId, user);
    }

    /* ===== CREATE POST (ALUMNI & ADMIN ONLY) ===== */
    @PostMapping("/{groupId}/posts")
    @PreAuthorize("hasRole('ALUMNI') or hasRole('ADMIN')")
    public void createPost(@PathVariable Long groupId,
                           @RequestBody Map<String, String> body,
                           @AuthenticationPrincipal User user) {

        postService.createPost(
                groupId,
                body.get("title"),
                body.get("content"),
                user
        );
    }


    /* ===== DELETE POST (ADMIN OR OWNER) ===== */
    @DeleteMapping("/posts/{postId}")
    @PreAuthorize("hasRole('ADMIN') or @postSecurity.isOwner(#postId, principal)")
    public void deletePost(@PathVariable Long postId) {
        postService.deletePost(postId);
    }
}
