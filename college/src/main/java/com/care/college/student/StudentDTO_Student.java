package com.care.college.student;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class StudentDTO_Student {
    private int student_No;
    private String name;
    private String department_Name;
    private String grade;
    private String password;
    private String tel;
    private String email;
    private String birth;
    private String address;
}
