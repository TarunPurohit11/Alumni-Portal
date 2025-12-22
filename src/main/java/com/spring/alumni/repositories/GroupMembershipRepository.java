package com.spring.alumni.repositories;

import com.spring.alumni.entities.GroupMembership;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface GroupMembershipRepository extends JpaRepository<GroupMembership, Long> {

    boolean existsByUserIdAndGroupId(Long userId, Long groupId);

    Optional<GroupMembership> findByUserIdAndGroupId(Long userId, Long groupId);
}

