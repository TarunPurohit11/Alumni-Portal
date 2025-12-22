package com.spring.alumni.repositories;

import com.spring.alumni.entities.Event;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;

public interface EventRepository extends JpaRepository<Event, Long> {

    Page<Event> findByEventDateAfter(LocalDate date, Pageable pageable);

    Page<Event> findByEventDateBefore(LocalDate date, Pageable pageable);
}
