package com.spring.alumni.controllers;

import com.spring.alumni.entities.User;
import com.spring.alumni.services.StudentUploadService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/admin/upload")
@RequiredArgsConstructor
public class StudentUploadController {

    private final StudentUploadService uploadService;

    @PostMapping("/students")
    public ResponseEntity<List<User>> uploadStudents(@RequestParam("file") MultipartFile file) throws Exception {
        return ResponseEntity.ok(uploadService.uploadStudents(file));
    }
}
