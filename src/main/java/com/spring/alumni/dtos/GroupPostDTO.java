package com.spring.alumni.dtos;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class GroupPostDTO {

    private Long id;
    private String title;
    private String content;
    private String createdByName;
    private Long createdById;
    private boolean ownPost;
    private LocalDateTime createdAt;

    // ✅ EXPLICIT constructor for JPQL
    public GroupPostDTO(
            Long id,
            String title,
            String content,
            String createdByName,
            Long createdById,
            boolean ownPost,
            LocalDateTime createdAt
    ) {
        this.id = id;
        this.title = title;
        this.content = content;
        this.createdByName = createdByName;
        this.createdById = createdById;
        this.ownPost = ownPost;
        this.createdAt = createdAt;
    }
}
