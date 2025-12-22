package com.spring.alumni.repositories;

import com.spring.alumni.entities.Group;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface GroupRepository extends JpaRepository<Group, Long> {
    Page<Group> findByMembers_Id(Long userId, Pageable pageable);
}
