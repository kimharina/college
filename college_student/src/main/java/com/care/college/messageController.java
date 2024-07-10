package com.care.college;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class messageController {
	@Autowired messageService ms;

	@RequestMapping(value = "/student/phoneCheck", method = RequestMethod.POST)
	@ResponseBody
	public String sendSMS(@RequestParam("tel") String userPhoneNumber) { 		// 휴대폰 문자보내기
		int randomNumber = (int)((Math.random()* (9999 - 1000 + 1)) + 1000);	//난수 생성

		ms.certifiedPhoneNumber(userPhoneNumber,randomNumber);
		
		return Integer.toString(randomNumber);
	}

}
