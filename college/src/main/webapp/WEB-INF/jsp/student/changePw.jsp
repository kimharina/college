<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar_login.jsp"%>
<style>

	.name {
		width: 100px;
		font-weight: bold;
	}
	tr{
		height: 50px;
	}

	.save {
		height: 30px;
		width: 100px;
		font-size: 8pt;
		background-color: #a20131;
		color: #fff;
		border-radius: 5px;
		border-width: 1px;
		cursor: pointer;
		}
	#info {
		border: 5px solid #dcdcdc;
		border-radius: 5px;
		background-color: #dcdcdc;
		width: 600px;
		padding: 10px 10px 10px 10px;
		overflow: hidden;
	}

}
</style>
<script type="text/javascript">
	function allCheck() {
		let beforePw = document.getElementById('beforePw').value;
		let pw= document.getElementById('pw').value;
		let confirmPw = document.getElementById('confirmPw').value;
		var passwordRegex = /^(?=.*[!@#$%^&*(),.?:{}|<>])(?=.*[0-9a-zA-Z]).{8,15}$/;
		
		if (beforePw == "") {
			alert('현재 비밀번호를 입력하세요.');
			 return false;
		} else if (pw == "") {
	        alert('변경할 비밀번호를 입력하세요.');
	        return false;
		} else if (!passwordRegex.test(pw)) {
	        alert('비밀번호는 특수문자를 포함하고, 8~15자여야 합니다.');
	        return false;
		} else if (confirmPw == "") {
			alert('변경할 비밀번호 확인을 입력하세요.');
			 return false;
		} else if (confirmPw != pw) {
			alert('비밀번호 확인이 일치하지 않습니다. 다시 입력해주세요.');
			 return false;
		} else {
			// 응답 객체에서 Authorization 헤더를 가져오기
			var jwtToken = localStorage.getItem("Authorization");

			console.log('jwtToken : '+jwtToken);

			//토큰이 있다면 서버로 전송
			if (jwtToken) {
		     fetch('/student/changePwProc', {
		         method: 'POST',
		         headers: {
		         	'Content-Type': 'application/json',
		             Authorization: localStorage.getItem('Authorization'),
		         },
		         body: JSON.stringify({ 
		        	 beforePw: beforePw,
				     pw: pw,	 
				}),
		     })
		     .then(response => {
		         if (response.ok) {
		             // 서버에서의 응답이 성공적일 경우
		        	 return response.text();
		         } else {
		             // 로그인 실패 시 오류 메시지를 얻어옴
		             return response.text().then(errorMsg => Promise.reject(errorMsg));
		         }
		     })
		     .then(data => {
		    	 if(data === "비밀번호가 변경되었습니다. 다시 로그인 해주세요."){
			         // 서버에서의 추가 처리
			         console.log('토큰 검증 성공', data);
			         localStorage.removeItem("Authorization");
			         alert("변경 되었습니다. 다시 로그인 해주세요.");
			         window.location.href = '/student/login';
		    	 } else {
		    		 alert("다시 입력해주세요.");
			         window.location.href = '/student/changePw';
		    	 }
		     })
		     .catch(error => {
		         // 에러 처리
		         console.error('토큰 검증 실패:', error);
		         localStorage.removeItem("Authorization");
		         alert("다시 로그인 해주세요.");
		         window.location.href = '/student/login';
		     });
		    } else {
		     // 토큰이 없을 경우의 처리
		     console.log('토큰이 없습니다.');
		     localStorage.removeItem("Authorization");
		     alert("다시 로그인 해주세요.");
	         window.location.href = '/student/login';

		    }

		};


	}

	function newPw(){
		let pw = document.getElementById('pw').value;
		label = document.getElementById('label1');
		 // 비밀번호 규칙 정의: 특수문자 포함, 8~15자
	    var passwordRegex = /^(?=.*[!@#$%^&*(),.?:{}|<>])(?=.*[0-9a-zA-Z]).{8,15}$/;

	    // 비밀번호가 규칙에 맞는지 확인
	    if (!passwordRegex.test(pw)) {
	    	label.innerHTML ='비밀번호는 특수문자를 포함하고, 8~15자여야 합니다.';
	        // 폼 제출 방지
	        event.preventDefault();
	    } else {
	    	label.innerHTML ='';
	    } 
	}
	function confirmNewPw(){
		let pw = document.getElementById('pw');
		let confirmPw = document.getElementById('confirmPw');
		label = document.getElementById('label2');
		if(pw.value == confirmPw.value){
			label.innerHTML = ''
		}else {
			label.innerHTML = '일치하지 않습니다. 다시 입력해주세요.'
			// 폼 제출 방지
		    event.preventDefault();
		}	 
	}

</script>
<div id="contents" class="contents">
<ul class="list-icon" style="margin-bottom:10px">
	<li><b>비밀번호 변경</b></li>
</ul>
	<div class="form-search">
		<form  action="/student/changePwProc" method="post" id="f">
		<table id="change">
			<colgroup>
				<col width="150px">
				<col width="200px">
				<col>
			</colgroup>			
			<tbody>
				<tr>
					<th>학번</th>
					<td id="student_No" style="font-weight: bold;">${student.student_No }</td>
					
				</tr>
				<tr>
					<th>현재 비밀번호</th>
					<td><input type="password" name="beforePw" id="beforePw" placeholder="현재 비밀번호" size="20" maxlength="15"></td>
					<td></td>
				</tr>
				<tr>
					<th>변경할 비밀번호</th>
					<td><input type="password" name="pw" id="pw" size="20" placeholder="특수문자 포함, 8~15자" onchange="newPw()" maxlength="15"></td>
					<td><label id="label1" style="color: red;"></label></td>
				</tr>
				<tr>
					<th>변경할 비밀번호 확인</th>
					<td><input type="password" name="confirmPw" id="confirmPw" placeholder="특수문자 포함, 8~15자" size="20" onchange="confirmNewPw()" maxlength="15"></td>
					<td><label id="label2" style="color: red;"></label></td>
				</tr>
				<tr>
					<td></td>
					<td>
						<button type="button" id="btnSearch" class="btn-sub" onclick="allCheck()">변경</button>
						<button type="button" id="btnReset" onclick="location.href='/student/myInfo'">취소</button>

					</td>
					<td></td>
				</tr>
			</tbody>
		</table>				
		</form>
	</div>
</div>

</body>
</html>