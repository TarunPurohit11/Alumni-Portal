package com.spring.alumni.entities;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StudyMaterial {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /* Which group this material belongs to */
    @ManyToOne(optional = false)
    private Group group;

    /* Title shown to user */
    @Column(nullable = false)
    private String title;

    /* URL of PDF / Video / Article */
    @Column(nullable = false, length = 1000)
    private String resourceUrl;

    /* PDF | VIDEO | ARTICLE */
    @Column(nullable = false)
    private String type;

    /* Optional difficulty tag */
    private String level; // BASIC / MEDIUM / ADVANCED
}

