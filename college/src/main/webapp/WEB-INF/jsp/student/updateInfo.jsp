<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar_login.jsp"%>
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script type="text/javascript">
	function sample6_execDaumPostcode() {
		new daum.Postcode(
				{
					oncomplete : function(data) {
						// 팝업에서 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

						// 각 주소의 노출 규칙에 따라 주소를 조합한다.
						// 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
						var addr = ''; // 주소 변수

						//사용자가 선택한 주소 타입에 따라 해당 주소 값을 가져온다.
						if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
							addr = data.roadAddress;
						} else { // 사용자가 지번 주소를 선택했을 경우(J)
							addr = data.jibunAddress;
						}

						// 우편번호와 주소 정보를 해당 필드에 넣는다.
						document.getElementById('sample6_postcode').value = data.zonecode;
						document.getElementById("sample6_address").value = addr;
						// 커서를 상세주소 필드로 이동한다.
						document.getElementById("sample6_detailAddress")
								.focus();
					}
				}).open();
	}
function allCheck() {
	let tel = document.getElementById('tel');
	let email = document.getElementById('email');
	let birth = document.getElementById('birth');
	let postcode = document.getElementById('sample6_postcode');
	let address = document.getElementById('sample6_address');
	let detailAddress = document.getElementById('sample6_detailAddress');

	if (tel.value == "") {
		alert('전화번호를 입력해주세요.');
		
	} else if (email.value == "") {
		alert('이메일을 입력해주세요.');
		
	} else if (birth.value == "" ) {
        alert("생년월일을 입력해주세요.");
        
	} else if (postcode.value == "") {
		alert('우편번호를 입력해주세요.');
		
	} else if (address.value == "") {
		alert('주소를 입력해주세요.');
		
	} else if (detailAddress.value == "") {
		alert('상세주소를 입력해주세요.'); 
	} else {

		// 응답 객체에서 Authorization 헤더를 가져오기
		var jwtToken = localStorage.getItem("Authorization");

		console.log('jwtToken : '+jwtToken);

		//토큰이 있다면 서버로 전송
		if (jwtToken) {
	     fetch('/student/updateInfo', {
	         method: 'POST',
	         headers: {
	         	'Content-Type': 'application/json',
	             Authorization: localStorage.getItem('Authorization'),
	         },
	         body: JSON.stringify({ 
			        	 tel: tel.value,
			             email: email.value,	 
			             birth: birth.value,	 
			             postcode: postcode.value,	 
			             address: address.value,	 
			             detailAddress: detailAddress.value,	 
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
	         // 서버에서의 추가 처리
	         console.log('토큰 검증 성공', data);
	         alert("수정 되었습니다.");
	         window.location.href = '/student/myInfo';
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
	
</script>
<style>

	.name {
		width: 100px;
		font-weight: bold;
	}
	tr{
		height: 40px;
	}
	.btn {
		height: 25px;
		width: 40px;
		font-size: 8pt;
		background-color: #a20131;
		color: #fff;
		border-radius: 5px;
		border-width: 1px;
		cursor: pointer;
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
		border: 1px solid #c8c8c8;
		border-radius: 3px;
		background-color: #dcdcdc;
		width: 600px;
		padding: 10px 1px 10px 5px;
		overflow: hidden;
	}

}
</style>
<div id="contents" class="contents">

<div align="center">
	<h1>내 정보</h1>
	<img src="/img/profile.png" alt="Profile Image" width="100" height="100">
		<div id="info">
			<form action="/student/updateInfo" method="post" id="f">
				<table style="width: 500px;">
					<tr>
						<td><h3 id="department_Name">${student.department_Name}</h3></td>
						<td></td>
						<td></td>
					</tr>
					<tr>
						<td id="student_No">${student.student_No}</td>
						<td id="name" style="font-weight: bold;">${student.name}</td>
						<td></td>
					</tr>
	
					<tr>
						<td class="name">전화번호 : </td>
						<td><input size="30" type="text" placeholder="전화번호(000-0000-0000)" name="tel" id="tel" class="tel" value="${student.tel }"></td>
						<td></td>
					</tr>
					<tr>
						<td class="name">이메일 : </td>
						<td><input size="30" type="email" placeholder="이메일" name="email" id="email"  class="email"value="${student.email }"></td>
						<td></td>
					</tr>
					<tr>
						<td class="name">생년월일 : </td>
						<td><input size="30" type="text" placeholder="생년월일(6글자)" name="birth" id="birth"  class="birth"value="${student.birth}" maxlength="6"></td>
						<td></td>
					</tr>
					<tr>
						<td class="name">주소 : </td>
						<td><input size="30" type="text" placeholder="우편번호" id="sample6_postcode" name="postcode"  class="postcode"value="${postcode }"></td>
						<td><button type="button" class="btn" onclick="sample6_execDaumPostcode()">검색</button></td>
					</tr>
					<tr>
						<td class="name"></td>
						<td><input size="30" type="text" placeholder="주소" id="sample6_address" name="address"  class="address"value="${address }"></td>
						<td></td>
					</tr>
					<tr>
						<td class="name"></td>
						<td><input size="30" type="text" placeholder="상세주소" id="sample6_detailAddress" name="detailAddress"  class="detailAddress"value="${detailAddress }"></td>	
						<td></td>
					</tr>
					<tr>
						<td colspan="3" align="center">
							<button type="button" class="save" onclick="allCheck()">수 정</button>
							<button type="button" class="save" onclick="location.href='/student/myInfo'">취 소</button>
						</td>
					</tr>
				</table>
			</form>
	</div>
</div>
</div>
</body>
</html>