<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>    
<html lang="ko">
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Expires" content="0">
<meta http-equiv="Pragma" content="no-cache">
<link rel="shortcut icon" href="/img/favicon.png">
<title>::카리나대학교 수강신청 시스템::</title>
<link href="/css/korea-ui.css?fake=1702989602929" rel="stylesheet" type="text/css">
<style>
.sname {
    font-size: 15px;
    line-height: 22px;
}
body.login .wrap-contents .wrap-schedule>div .schedule {
    position: relative;
    height: auto;
}
body.login .wrap-contents h1 {
    margin-bottom: 5px;
}    
.jconfirm .jconfirm-box div.jconfirm-content-pane .jconfirm-content {
    /* overflow: scroll; */
    max-height:600px;
}
a, a:focus, a:active, a:hover, a:visited {
    color: #528ecc;
    text-decoration: none;/* underline; */
    outline: 0 none;
}
</style>


</head>
<body class="login">
	<div class="wrap-loader" style="display:none;"><span class="loading-helper"></span><div class="loader"></div><div class="loading-text">Loading</div></div>
	<div class="header" >
		<a href="/student/index"><img src="/img/karina_white.png" width="250px"  onclick="location.href='/student/index'"></a>

	</div>
	
	<div class="wrap-login">
	 	<div class="slide-bg">
              <div class="bg">
                <video id="banner-video00" playsinline="" muted="" autoplay="" loop="">
                  <source src="https://www.snu.ac.kr//webdata/uploads/kor/media/2023/12/movie_20231220_kor.mp4" type="video/mp4">
                </video>
        	</div>
        </div>
    
		<div>
			<div class="login-box" style="height:360px">
			<div class="wrap-lang">					
					<input type="radio" name="lang" value="KOR" id="kor" checked=""><label for="kor">KOREAN</label>
					<input type="radio" name="lang" value="ENG" id="eng"><label for="eng">ENGLISH</label>
			</div>
				<div id="loggedInMessage" style="display: none;">
					<table>
					<tr>
						<td rowspan="2"><img src="/img/profile.png" alt="Profile Image" width="80" height="80"></td>
			        	<td><b><div id="studentNo">${student_No }</div></b></td>
			        	<td rowspan="2"><button type="button" id="btn-login" class="btn-login" onclick="logout()">로그아웃<small>Logout</small></button></td>
			        </tr>
			        <tr>        	
			            <td><b><div id="name">${name }</div></b></td>
			        </tr>
			        <tr class="admin hidden">
			        	
			        	<td colspan="2" align="center"><button onclick="location.href='/student/admin_index'">관리자 시스템</button></td>
			        	<td></td>
			        </tr>
					</table>
	       		</div>
				<form id="f" name="loginForm" action="/student/loginProc" method="post" autocomplete="off">
					<input type="text" id="student_no" name="student_no" class="input-id" placeholder="학번 ( Student ID )">
					<input type="password" id="password" name="password" class="input-pw" placeholder="비밀번호 ( Password )" maxlength="15">
				<button type="button" id="btn-login" class="btn-login" onclick="loginCheck()">로그인<small>Login</small></button>
				</form>		
			</div>
		</div>

	</div>

<div class="wrap-contents">
		<div>
			<h1>수강신청 안내<small>Course Registration Schedule</small></h1>
			<div class="wrap-schedule">
				<div>
					<h2>학부 수강신청 일정<small></small></h2>
					<div class="schedule">
						<p><span class="sname">학부 수강신청 안내</span><span class="btn-more" onclick="location.href='/sugang/info'" id="menu_noti_1"></span></p>
						<!-- <div class="time"><span>2020.05.02  09:00</span><span class="unit">-</span><span>2020.05.13  17:00</span></div> -->
					</div>
				</div>
				<div>
					<h2>과목조회<small></small></h2>
					<div class="schedule">
						<p><span class="sname">카리나대학교 과목조회</span><span class="btn-more" onclick="location.href='/sugang/cart'" id="menu_hakbu"></span></p>
						<!-- <div class="time"><span>2020.05.02  09:00</span><span class="unit">-</span><span>2020.05.13  17:00</span></div> -->
					</div>
				</div>
				<div>
					<h2>교육정보<small></small></h2>
					<div class="schedule">
						<p><span class="sname">카리나대학교<br>교육정보 확인</span><a href="http://registrar.korea.ac.kr/" target="_blank"><span class="btn-more"></span></a></p>
						<!-- <div class="time"><span>2020.05.02  09:00</span><span class="unit">-</span><span>2020.05.13  17:00</span></div> -->
					</div>
				</div>
				<div>
					<h2>학번 조회<small></small></h2>
					<div class="schedule">
						<p><span class="sname">학번조회 &nbsp;&nbsp;&nbsp;</span><span class="btn-more" onclick="location.href='/student/searchStNum'" id="menu_stdno"></span></p>
						<!-- <div class="time"><span>2020.05.02  09:00</span><span class="unit">-</span><span>2020.05.13  17:00</span></div> -->
					</div>
				</div>

			</div>
			
			<h1>수강신청 유의사항<small>Course Registration Notice</small></h1>
			



<div class="info-box" id="boxENG" style="display:none">	
	<ul class="list-icon">
		<!-- <li><span style="font-weight:bold; color:red; text-decoration:underline;">On-line enrollment process for the senior class will begin at 2:00 pm today due to a computer system error. </li> --> 
		<li>Before registering for courses, you are kindly asked to review the course registration instructions provided by the</li> 
		<li style="background: url(); ">relevant college/division. You can find the menu on the left side of the screen. </li>

		<li>
			<a href="javascript:fnExploer()"><span class="font_green">When log in fails, how to change Internet Explore setting</span></a>
		</li>
		
		<li>Please use Chrome, Firefox, and Edge browsers according to Microsoft's Internet Explorer termination policy.</li>
		<li><a href="/resources/manual/suganginfoeng.pdf" target="_blank"><span style="font-weight:bold; color:red; text-decoration:underline;">Q&amp;A about Revised Course Registration System from 2nd Semester, 2018 (Important!!)</span></a></li>
		
		<li><span class="txt-red">You can register for courses restricted by certain departments during the course change period (Add/Drop period) in
			 the first week of the semester. (March or September)</span></li>
		
		<li>The College of Life and Environmental Sciences and the College of Life Sciences and Biotechnology have been</li>
		<li style="background: url(); ">merged into the College of Life Sciences and Biotechnology since March 2006. Undergraduate students admitted to </li> <li style="background: url();">either college should register for courses offered by the College of Life Sciences and Biotechnology. </li>
		
		<li>
			<span class="bold">Password</span> : New students/non-KU students: Input the last 7 digits of your resident registration number.
		</li>
		<li style="background: url(); padding-left:53px;">KU portal users: Input your KUPID Password.</li>
		<li style="background: url(); padding-left:53px;">Non-KU portal users: Input your existing intranet password.</li>
		
		<li>Student number for non-Korea University student</li>
		<li style="background: url(); ">If you are a non-Korea University student (undergraduate only), please refer to Korea University Home page-&gt;academic</li><li style="background: url(); "> exchange-&gt;domestic student exchange site for your student number at Korea University.  </li>

		<li><span class="font_red"><strong>If you have forgotten your password</strong></span> , you may find your password at the log-in page of </li>
		<li style="background: url(); "><a href="http://portal.korea.ac.kr" target="_blank">KU portal (http://portal.korea.ac.kr)</a> site. Use the 'PW inquiry' button.</li>
	</ul>
</div>
<div class="info-box" id="boxKOR">
	<ol>
		<ul class="list-icon">
			<li><a href="javascript:fnNotice()">수강신청시스템 중복로그인/매크로 제한 기능 도입 안내</a></li>
			<div id="notiMacro" style="display:none;">
			<ul style="margin-left: 18px;"><li>
				2013학년도 2학기 수강신청부터(2013학년도 여름계절수업 시범 운영) 모든 사용자에게 공정하고 원활한 수강신청 서비스를 제공하고자<br>
				아래와 같은 제한 기능을 도입하오니 학생 여러분께서는 수강신청 시 아래 내용을 필히 숙지하여 주시기 바랍니다.<br>
				아래 기능 도입으로 인하여 본인의 아이디와 패스워드를 타인에게 빌려주면 원치 않게 로그아웃이 될 수 있으니, 본인 계정 관리에 신중을 기하여 주시기 바랍니다.</li>
			</ul>
			<p>&nbsp;</p>					
			<ul class="list-num" style="margin-left: 30px;">
				<li>중복로그인 방지 기능
					<ul class="list-dot">
						<li>동일 아이디로 두 명 이상이 로그인하면 가장 마지막에 로그인 한 사용자만 수강신청이 가능합니다.</li>
					</ul>
				</li>
				<li>매크로 방지 기능
					<ul class="list-dot">
						<li>수강신청저장을 일정횟수를 초과하여 시도 할 때마다 임의의 문자열 이미지를 무작위로 화면에 표시하고 문자열을 올바르게 입력 했을 경우 수강신청 저장이 가능합니다.</li>
					</ul>
				</li>							
			</ul>
			</div>
		</ul>	
	</ol>
	
	<ul class="list-icon">
		<li>Microsoft의 Internet Explorer 지원 종료에 따라 Chrome, Firefox, Edge 브라우저를 이용하시기 바랍니다.</li>
		<li class="highlight">장애학생 수강신청 - 8. 1(화) 10:00 - 8. 2(수) 09:00</li>
		<li class="highlight">수강희망과목 등록기간 - 8. 2(수) 13:00 - 8. 4(금) 12:00</li>
		<li class="highlight">신입생 수강신청 기간 - 8. 22(화) 10:00 - 8. 23(수) 12:00</li>
		<li class="highlight">수강신청 기간 - 8. 16(수) 10:00부터 시작, 4학년을 시작으로 학년별로 수강신청을 진행함.</li>
		<li class="highlight">수강신청 정정 기간 - 9. 6(수) 18:30부터 시작, 4학년을 시작으로 학년별로 한 시간 간격으로 시작시간을 달리함.</li>
		<li class="highlight">수강 및 성적평가 공정성 제고 관련 교육부 권고에 따라, 부모 중 1인 이상이 강의를 담당하는 과목의 경우 자녀의 수강이 제한될 수 있습니다.</li>
		<li>학사관련 주요사항 안내는 교육정보 홈페이지를 참조하세요. <a href="http://registrar.korea.ac.kr" target="_blank">교육정보 바로가기</a></li>
		<li>단과대학별 수강신청 유의사항은 교육정보 홈페이지를 참조하세요. <a href="http://registrar.korea.ac.kr/eduinfo/info/registration_caution.do" target="_blank">교육정보 바로가기</a></li>
		<li><b>암호</b>			
			<ul class="list-dot">
				<li>포털(KUPID)사용자 : 포털비밀번호</li>
				<li>포털(KUPID)미사용자 : '포털미사용자 비밀번호변경'에서 설정한 비밀번호(설정전: 주민번호뒷자리)</li>
				<li>(포털사용중인 신입생도 개강전에는 포털미사용자에 해당하는 비밀번호 사용)</li>
			</ul>
		</li>
		<li><b>암호 분실시</b>	
			<ul class="list-dot">
				<li>포털 사용자 : <a href="http://portal.korea.ac.kr" target="_blank">포털(http://portal.korea.ac.kr)</a> 로그인 화면의 <strong>'비밀번호찾기'</strong>에서 비밀번호 재발급</li>
				<li>포털(KUPID)미사용자 : <span class="txt-blue">수강신청(https://sugang.korea.ac.kr)</span> <strong>'포털미사용자 비밀번호변경'</strong> 메뉴에서 비밀번호 재발급</li>
				<li class="highlight">포털에서 비밀번호를 변경 또는 재발급 받은 경우는 10분후에 로그인 하기 바랍니다.</li>
			</ul>
		</li>
		<li><a href="javascript:fnExchange()">국내 교류 학생의 학번 확인</a></li>
		<li>Internet Explorer 10 이상의 버전, 화면 해상도 1920*1080에 최적화 되어 있습니다.</li>
	</ul>
</div>

		</div>
	</div>
	
	<div class="footer">
		<div>
			02841 서울특별시 성북구 안암로 145 / TEL.02.3290.1114. / webmaster@korea.ac.kr<br>Copyright © 2020 Korea University. All Rights Reserved
		</div>
	</div>
	

</body>
</html>
<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>

<script defer>
// 페이지 로딩 시에 실행되는 함수
window.onload = function () {
	//let jwtToken = response.headers.get('Authorization');
	// 응답 객체에서 Authorization 헤더를 가져오기
	var jwtToken = localStorage.getItem("Authorization");

	console.log('jwtToken : '+jwtToken);

	//토큰이 있다면 서버로 전송
	if (jwtToken) {
     fetch('/student/validateToken', {
         method: 'POST',
         headers: {
             'Content-Type': 'application/json',
         },
         body: JSON.stringify({ token: jwtToken }),
     })
     .then(response => {
         if (response.ok) {
        	// Content-Type이 application/json인 경우
             if (response.headers.get('Content-Type').includes('application/json')) {
                 return response.json(); // JSON 형식으로 파싱
             } else {
                 return response.text(); // 다른 형식의 데이터는 텍스트로 직접 받음
             }
         } else {
             // 로그인 실패 시 오류 메시지를 얻어옴
             return response.text().then(errorMsg => Promise.reject(errorMsg));
         }
     })
     .then(response => {
         // 서버에서의 추가 처리
         console.log('토큰 검증 성공', response);
      // 로그인 폼 숨기기
         document.getElementById('f').style.display = 'none';
 		//로그아웃 폼
         document.getElementById('loggedInMessage').style.display = 'block';
 		
         const studentNoElement = document.querySelector('#studentNo');
         const nameElement = document.querySelector('#name');

         // 데이터가 존재하는 경우에만 각 항목에 데이터 출력
         if (studentNoElement) studentNoElement.textContent = response.student_No;
         if (nameElement) nameElement.textContent = response.name;
         
		// 관리자페이지링크 표시
         if (response.name == "admin") $(".admin").removeClass("hidden");
         else $(".admin").addClass("hidden"); 
     })
     .catch(error => {
         // 에러 처리
         console.error('토큰 검증 실패:', error);
         localStorage.removeItem("Authorization");
         // jwtToken이 없으면 로그인 폼 보이기
         document.getElementById('f').style.display = 'block';
         // 로그아웃 또는 토큰이 만료되었을 때 로컬 스토리지에서 토큰 제거
     });
    } else {
     // 토큰이 없을 경우의 처리
     console.log('토큰이 없습니다.');
     localStorage.removeItem("Authorization");
     // jwtToken이 없으면 로그인 폼 보이기
     document.getElementById('f').style.display = 'block';
     // 로그아웃 또는 토큰이 만료되었을 때 로컬 스토리지에서 토큰 제거
    }

};

function logout(){
	localStorage.removeItem("Authorization");
    alert("로그아웃 되었습니다.");
    window.location.href = '/student/login';
}
</script>
<script type="text/javascript">
function handleLoginSuccess(response) {
    // 헤더를 확인하고 null이 아니면 출력
    let jwtToken = response.headers.get('Authorization');
    if (jwtToken !== null) {
        console.log('Authorization: ' + jwtToken);
        // 토큰을 로컬 스토리지에 저장 또는 필요한 처리 수행
        localStorage.setItem('Authorization', jwtToken);
    } else {
        console.log('Authorization 헤더가 응답에 존재하지 않습니다.');
    }

    // jwtToken이 있으면 로그인되어 있다고 간주
    if (jwtToken) {
        // 로그인 폼 숨기기
        document.getElementById('f').style.display = 'none';
        // 로그아웃 폼
        document.getElementById('loggedInMessage').style.display = 'block';
        // 토큰 값을 로컬 스토리지에 저장
        localStorage.setItem("Authorization", jwtToken);
    } else {
        // jwtToken이 없으면 로그인 폼 보이기
        document.getElementById('f').style.display = 'block';
        // 로그아웃 또는 토큰이 만료되었을 때 로컬 스토리지에서 토큰 제거
        localStorage.removeItem("Authorization");
    }
};

function loginCheck() {
    let student_no = document.getElementById('student_no');
    let password = document.getElementById('password');

    if (student_no.value === "" || password.value === "") {
        alert('학번과 비밀번호는 필수 항목입니다.');
    } else {
        fetch('/student/loginProc', {
            method: 'POST',
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                student_no: student_no.value,
                password: password.value,
            }),
        })
        .then(response => {
        	 if (response.ok) {
                 // 로그인 성공 시 토큰을 얻어옴
                 handleLoginSuccess(response);
                 return response.text();
        
             } else {
                 // 로그인 실패 시 오류 메시지를 얻어옴
                 return response.text().then(errorMsg => Promise.reject(errorMsg));
             }
         })
        .then(data => {

	            // 로그인 성공의 경우
	            if (data === "학생 로그인 성공") {
	                console.log(data);
	                window.location.href = '/student/login';
	    			
	            }
	            // 관리자 로그인 성공의 경우
	            else if (data === "관리자 로그인 성공") {
	                console.log('관리자 로그인 성공:', data);
	                window.location.href = '/student/login';

	            }
	            // 비밀번호 변경 요청의 경우
	            else if (data === "비밀번호를 변경해주세요.") {
	                console.log(data);
	                alert('비밀번호를 변경해주세요.');
	                // 페이지 이동
	                window.location.href = '/student/changePw';

	            }
	            // 학번 비밀번호 불일치
	            else if (data === "학번 또는 비밀번호를 확인 후 다시 입력하세요.") {
	                console.log(data);
	                alert('학번 또는 비밀번호를 확인 후 다시 입력하세요.');

	            }
	         // 학번 문자 입력 시
	            else if (data === "학번은 숫자로 입력하세요.") {
	                console.log(data);
	                alert('학번은 숫자로 입력하세요.');

	            }
            
        })
        .catch(error => {
        	// 로그인 실패 또는 기타 오류의 경우
            console.error('Login failed:', error);

            if (error.status === 401) {
                alert('로그인에 실패했습니다. 학번 또는 비밀번호를 확인 후 다시 입력하세요.');
            } else {
                alert('오류 발생: ' + error.data);
            }
        });
    }
};

$(document).ready(function() {
    // 엔터 키 감지
    $('#f input').keydown(function(e) {
        if (e.keyCode == 13) {
        	loginCheck();
        }
    });
});


</script>