package com.spring.alumni.repositories;

import com.spring.alumni.entities.Announcement;
import com.spring.alumni.entities.type.Status;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AnnouncementRepository extends JpaRepository<Announcement, Long> {

    List<Announcement> findByStatusOrderByPublishedAtDesc(Status status);

}
