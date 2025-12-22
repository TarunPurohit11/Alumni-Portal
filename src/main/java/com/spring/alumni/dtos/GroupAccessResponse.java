package com.spring.alumni.dtos;

import com.spring.alumni.entities.StudyMaterial;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

@Data
@AllArgsConstructor
public class GroupAccessResponse {

    /* Can user enter group page? */
    private boolean allowed;

    /* Should assessment be shown? */
    private boolean assessmentRequired;

    /* When user can retry (null if not applicable) */
    private LocalDateTime retryAfter;

    /* Study materials shown when user fails */
    private List<StudyMaterial> studyMaterials;

    /* ================= FACTORY METHODS ================= */

    public static GroupAccessResponse allowed() {
        return new GroupAccessResponse(
                true,
                false,
                null,
                null
        );
    }

    public static GroupAccessResponse requireAssessment() {
        return new GroupAccessResponse(
                false,
                true,
                null,
                null
        );
    }

    public static GroupAccessResponse cooldown(LocalDateTime retryAfter) {
        return new GroupAccessResponse(
                false,
                false,
                retryAfter,
                null
        );
    }

    public static GroupAccessResponse cooldown(
            LocalDateTime retryAfter,
            List<StudyMaterial> materials) {

        return new GroupAccessResponse(
                false,
                false,
                retryAfter,
                materials
        );
    }

}

