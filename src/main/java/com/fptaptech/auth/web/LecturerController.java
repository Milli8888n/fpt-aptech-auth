package com.fptaptech.auth.web;

import com.fptaptech.auth.domain.AppUser;
import com.fptaptech.auth.repository.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/lecturer")
public class LecturerController {

    private final UserRepository userRepository;

    public LecturerController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/students")
    public String studentsList(
            @RequestParam(value = "page", defaultValue = "0") int page,
            @RequestParam(value = "size", defaultValue = "10") int size,
            Model model) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("id").descending());
        Page<AppUser> studentsPage = userRepository.findAllStudents(pageable);

        model.addAttribute("studentsPage", studentsPage);
        model.addAttribute("currentPage", page);
        return "lecturer/students";
    }
}
