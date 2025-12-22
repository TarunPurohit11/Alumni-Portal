package com.spring.alumni.services;

import com.spring.alumni.dtos.AnnouncementDTO;
import com.spring.alumni.entities.Announcement;
import com.spring.alumni.entities.type.Status;
import com.spring.alumni.repositories.AnnouncementRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AnnouncementServices {

    private final AnnouncementRepository announcementRepository;


    public List<Announcement> getAllActiveAnnouncements() {
        List<Announcement> announcements = announcementRepository.findByStatusOrderByPublishedAtDesc(Status.ACTIVE);
        return announcements != null ? announcements : Collections.emptyList();
    }

    public Announcement createAnnouncement(AnnouncementDTO dto) {
        Announcement announcement = Announcement.builder()
                .title(dto.getTitle())
                .shortDescription(dto.getShortDescription())
                .content(dto.getContent())
                .imageUrl(dto.getImageUrl())
                .status(Status.ACTIVE)
                .build();
        return announcementRepository.save(announcement);
    }
}
