package com.care.college;

import java.util.HashMap;

import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import net.nurigo.java_sdk.api.Message;
import net.nurigo.java_sdk.exceptions.CoolsmsException;

@Service
public class messageService {
	
	 @Value ("${message.api_key}") private String api_key;	
	 @Value ("${message.api_secret}") private String api_secret;

	public void certifiedPhoneNumber(String userPhoneNumber, int randomNumber) {
		
	    Message coolsms = new Message(api_key, api_secret);
	    
	    //4 params(to, from, type, text)
	    HashMap<String, String> params = new HashMap<String, String>();
	    params.put("to", userPhoneNumber);    	// 수신전화번호
	    params.put("from", "01072510815");    	// 발신전화번호. 테스트시에는 발신,수신 둘다 본인 번호로 하면 됨
	    params.put("type", "SMS");
	    params.put("text", "[college] 인증번호는" + "["+randomNumber+"]" + "입니다."); 	// 문자 내용 입력
	    params.put("app_version", "test app 1.2"); 						
	    System.out.println("[college] 인증번호는" + "["+randomNumber+"]" + "입니다.");
	    try {
	        JSONObject obj = (JSONObject) coolsms.send(params);
	        System.out.println(obj.toString());
	      } catch (CoolsmsException e) {
	        System.out.println(e.getMessage());
	        System.out.println(e.getCode());
	      }
	}
	
}
