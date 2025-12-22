package com.spring.alumni.repositories;

import com.spring.alumni.dtos.PublicProfileDTO;
import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.AuthProviderType;
import com.spring.alumni.entities.type.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findByProviderIdAndProviderType(String providerId, AuthProviderType providerType);

    List<User> findAllByRole(Role role);

    @Query("""
                SELECT new com.spring.alumni.dtos.PublicProfileDTO(
                    u.id,
                    u.name,
                    u.company,
                    u.title,
                    u.year,
                    u.profilePic
                )
                FROM User u
                WHERE u.role = com.spring.alumni.entities.type.Role.ALUMNI
            """)
    Page<PublicProfileDTO> findPublicAlumni(Pageable pageable);


    Page<User> findByRole(Role role, Pageable pageable);
}
