package com.spring.alumni.controllers;

import com.spring.alumni.dtos.AdminActionResponseDTO;
import com.spring.alumni.dtos.AdminUserResponseDTO;
import com.spring.alumni.dtos.AnnouncementDTO;
import com.spring.alumni.dtos.EventDTO;
import com.spring.alumni.entities.Announcement;
import com.spring.alumni.entities.Event;
import com.spring.alumni.services.AdminService;
import com.spring.alumni.services.AnnouncementServices;
import com.spring.alumni.services.EventServices;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;
    private final EventServices eventServices;
    private final AnnouncementServices announcementServices;

    @GetMapping("/users")
    public Page<AdminUserResponseDTO> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size){
        return adminService.getAllUsers(page,size);
    }

    @PutMapping("/{id}/toggle")
    public ResponseEntity<AdminActionResponseDTO> toggleUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.toggleUser(id));
    }


    @DeleteMapping("/{id}")
    public ResponseEntity<AdminActionResponseDTO> deleteUser(@PathVariable Long id) {
        return ResponseEntity.ok(adminService.deleteUser(id));
    }

    @PostMapping("/create/event")
    public ResponseEntity<Event> createEvent(@RequestBody EventDTO dto) {
        return ResponseEntity.ok(eventServices.createEvent(dto));
    }

    @PostMapping("/create/announcement")
    public ResponseEntity<Announcement> createAnnouncement(@RequestBody AnnouncementDTO dto) {
        return ResponseEntity.ok(announcementServices.createAnnouncement(dto));
    }

}
