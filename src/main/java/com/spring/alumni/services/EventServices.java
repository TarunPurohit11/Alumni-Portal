package com.spring.alumni.services;

import com.spring.alumni.dtos.EventDTO;
import com.spring.alumni.entities.Event;
import com.spring.alumni.entities.type.Status;
import com.spring.alumni.repositories.EventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Collections;
import java.util.List;

@Service
@RequiredArgsConstructor
public class EventServices {

    private final EventRepository eventRepository;

    public Page<Event> getUpcomingEvents(int page, int size) {
        Pageable pageable = PageRequest.of(page,size, Sort.by("createdAt").ascending());
        return eventRepository.findByEventDateAfter(LocalDate.now(),pageable);
    }

    public Page<Event> getArchivedEvents(int page,int size) {
        Pageable pageable = PageRequest.of(page,size,Sort.by("createdAt").descending());
        return eventRepository.findByEventDateBefore(LocalDate.now(),pageable);
    }

    public Event createEvent(EventDTO dto) {
        Event event = Event.builder()
                .title(dto.getTitle())
                .shortDescription(dto.getShortDescription())
                .content(dto.getContent())
                .eventDate(dto.getEventDate())
                .imageUrl(dto.getImageUrl())
                .status(Status.ACTIVE)
                .build();
        return eventRepository.save(event);
    }
}
