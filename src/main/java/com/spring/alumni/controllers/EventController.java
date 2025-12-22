package com.spring.alumni.controllers;

import com.spring.alumni.entities.Announcement;
import com.spring.alumni.entities.Event;
import com.spring.alumni.services.AnnouncementServices;
import com.spring.alumni.services.EventServices;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/events")
@CrossOrigin
public class EventController {

    private final EventServices eventServices;

    @GetMapping("/upcoming")
    public Page<Event> getUpcomingEvents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "5") int size){
        return eventServices.getUpcomingEvents(page, size);
    }

    @GetMapping("/past")
    public Page<Event> getArchivedEvents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "8") int size){
        return eventServices.getArchivedEvents(page,size);
    }

}
