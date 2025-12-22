package com.spring.alumni.controllers;

import com.spring.alumni.entities.User;
import com.spring.alumni.services.StudentServices;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/student")
@RequiredArgsConstructor
public class StudentController {

    private final StudentServices studentServices;

    @GetMapping
    public Page<User> getAllStudents(@RequestParam(defaultValue = "0") int page,
                                     @RequestParam(defaultValue = "8") int size){
        return studentServices.getAllStudents(page,size);
    }
    @GetMapping("/api/all")
    public List<User> getAllStudents(){
        return studentServices.getUsers();
    }
}
