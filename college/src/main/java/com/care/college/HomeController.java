package com.care.college;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class HomeController {



	@RequestMapping("/student/index")
	public String index() {
		return "index";
	}
	
	@RequestMapping("header")
	public String header() {
		return "header";
	}
	
	@RequestMapping("footer")
	public String footer() {
		return "footer";
	}
	
	




}
