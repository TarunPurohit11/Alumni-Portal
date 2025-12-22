package com.spring.alumni.repositories;

import com.spring.alumni.entities.StudyMaterial;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface StudyMaterialRepository
        extends JpaRepository<StudyMaterial, Long> {

    List<StudyMaterial> findByGroupId(Long groupId);
}

