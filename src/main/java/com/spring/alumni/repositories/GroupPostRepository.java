package com.spring.alumni.repositories;

import com.spring.alumni.dtos.GroupPostDTO;
import com.spring.alumni.entities.GroupPost;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface GroupPostRepository extends JpaRepository<GroupPost, Long> {

    @Query("""
            SELECT new com.spring.alumni.dtos.GroupPostDTO(
                p.id,
                p.title,
                p.content,
                p.createdBy.name,
                p.createdBy.id,
                CASE WHEN p.createdBy.id = :userId THEN true ELSE false END,
                p.createdAt
            )
            FROM GroupPost p
            WHERE p.group.id = :groupId
            ORDER BY p.createdAt DESC
        """)
    List<GroupPostDTO> findGroupPosts(
            @Param("groupId") Long groupId,
            @Param("userId") Long userId
    );


    List<GroupPost> findByGroupId(Long groupId);
}
