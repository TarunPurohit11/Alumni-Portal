package com.spring.alumni.services;

import com.spring.alumni.entities.User;
import com.spring.alumni.entities.type.AuthProviderType;
import com.spring.alumni.entities.type.Role;
import com.spring.alumni.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class StudentUploadService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public List<User> uploadStudents(MultipartFile file) throws Exception {
        List<User> students = new ArrayList<>();
        Workbook workbook;
        try (InputStream is = file.getInputStream()) {
            workbook = WorkbookFactory.create(is); // automatically detects xls or xlsx
        }
        Sheet sheet = workbook.getSheetAt(0);

        for (Row row : sheet) {
            if (row.getRowNum() == 0) continue; // skip header

            String name = getCellStringValue(row.getCell(0));
            String username = getCellStringValue(row.getCell(1));
            String course = getCellStringValue(row.getCell(2));
            Integer year = getCellNumericValue(row.getCell(3));
            String city = getCellStringValue(row.getCell(4));

            if (name == null || username == null) {
                continue; // skip invalid rows
            }

            // Skip existing users
            Optional<User> existing = userRepository.findByUsername(username);
            if (existing.isPresent()) continue;

            User u = User.builder()
                    .name(name)
                    .username(username)
                    .role(Role.STUDENT)
                    .password(passwordEncoder.
                            encode("student@123")
                    )
                    .providerType(AuthProviderType.EMAIL)
                    .enabled(true)
                    .accountLocked(false)
                    .course(course)
                    .year(year)
                    .city(city)
                    .build();

            students.add(u);
        }

        workbook.close();
        return userRepository.saveAll(students);
    }

    // Helper: safely get string value
    private String getCellStringValue(Cell cell) {
        if (cell == null) return null;
        if (cell.getCellType() == CellType.STRING) return cell.getStringCellValue().trim();
        if (cell.getCellType() == CellType.NUMERIC) return String.valueOf((int) cell.getNumericCellValue());
        return null;
    }

    // Helper: safely get numeric value
    private Integer getCellNumericValue(Cell cell) {
        if (cell == null) return null;
        if (cell.getCellType() == CellType.NUMERIC) return (int) cell.getNumericCellValue();
        if (cell.getCellType() == CellType.STRING) {
            try {
                return Integer.parseInt(cell.getStringCellValue().trim());
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
}
