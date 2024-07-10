<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="ko"><head>
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<link rel="shortcut icon" href="/img/favicon.png">
<meta charset="UTF-8">
<title>::고려대학교 수강신청 시스템::</title>
<link href="/css/korea-ui.css" rel="stylesheet" type="text/css">

<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>
<script>
document.addEventListener("DOMContentLoaded", function () {
	//console.log("로컬스토리지: "+localStorage.getItem('Authorization'));
    fetch('/student/myInfo', {
        method: 'POST',
        headers: {
        	'Content-Type': 'application/json',
             Authorization: localStorage.getItem('Authorization'),
        },
    })
    .then(response => {
        // HTTP 상태 코드가 200 OK인 경우
        if (response.ok) {
            // Content-Type이 application/json인 경우
            if (response.headers.get('Content-Type').includes('application/json')) {
                return response.json(); // JSON 형식으로 파싱
            } else {
                return response.text(); // 다른 형식의 데이터는 텍스트로 직접 받음
            }
        } else {
            throw new Error('Network response was not ok.');
        }
    })
    .then(response => {
        console.log('토큰 검증 성공', response);
        if (response) {
            console.log(response);
            
            // 각 항목에 대한 데이터 가져오기
            const departmentElement = document.querySelector('#department_Name');
            const studentNoElement = document.querySelector('#student_No');
            const nameElement = document.querySelector('#name');
            const login_NameElement = document.querySelector('#login_Name');
            const telElement = document.querySelector('#tel');
            const emailElement = document.querySelector('#email');
            const birthElement = document.querySelector('#birth');
            const postcodeElement = document.querySelector('#postcode');
            const addressElement = document.querySelector('#address');
            const detailAddressElement = document.querySelector('#detailAddress');

            // 데이터가 존재하는 경우에만 각 항목에 데이터 출력
            if (departmentElement) departmentElement.textContent = response.student.department_Name;
            if (studentNoElement) studentNoElement.textContent = response.student.student_No;
            if (nameElement) nameElement.textContent = response.student.name;
            if (login_NameElement) login_NameElement.textContent = response.student.name;
            if (telElement) telElement.textContent = response.student.tel;
            if (emailElement) emailElement.textContent = response.student.email;
            if (birthElement) birthElement.textContent = response.student.birth;
            if (postcodeElement) postcodeElement.textContent = response.postcode;
            if (addressElement) addressElement.textContent = response.address;
            if (detailAddressElement) detailAddressElement.textContent = response.detailAddress;
         // 모든 input 요소에 대한 데이터 가져오기
            const inputElements = document.querySelectorAll('input');

            // 데이터가 존재하는 경우에만 각 input 요소에 데이터 설정
            inputElements.forEach(input => {
                const className = input.classList[0];

                if (response.student && response.student[className] !== undefined && className !== 'address') {
                    input.value = response.student[className];
                } else {
                	input.value = response[className] || "";
                }
            });
			//관리자일 경우 시간설정 탭 나오게하기
			if(response.student.name === "admin") {
				$(".timeSet").removeClass("hidden");
			}else{
				$(".timeSet").addClass("hidden");
			}
        } else {
        	console.log('토큰 유효하지 않음 또는 서버에서 반환된 데이터가 없음');
            localStorage.removeItem("Authorization");
            alert("로그인 해주세요.");
            window.location.href = '/student/login';
        }
    })
    .catch(error => {
        // 에러 처리
        console.error('토큰 검증 실패:', error);
        localStorage.removeItem("Authorization");
        alert("로그인 해주세요.");
        window.location.href = '/student/login';
    });
});

function logout(){
	localStorage.removeItem("Authorization");
    alert("로그아웃 되었습니다.");
    window.location.href = '/student/login';
}
</script>

<style>
.wrap-container .header .is-left .title_sub {
    /* margin-left: 12px;
    padding-left: 10px;
    border-left: 1px solid #ccc; */
    font-size: 20px;
    font-weight: 600;
    letter-spacing: -1px;
}0
.wrap-container .nav .nav-footer {
    height: 210px;
}   
.jconfirm .jconfirm-box {    
    max-width: 650px;
}
.jconfirm-content {
    /* overflow: scroll; */
    max-height:600px;
}
.list-num>li {
   margin-bottom: 10px;
    font-size: 13px;
    line-height: 18px;
    word-break: break-all;
}
/* 공백 */
.dataTables_scrollBody{
	background-color: #fff;
	/* border-bottom: 1px solid #ccc; */
}
.dataTables_wrapper .dataTables_processing {
   top: 64px !important;
    /* z-index: 100 !important; */
   height:100%;
}
table.dataTable .label-type+* {
    /* position: relative; */
    top: 0px;
    width: 20px;
}
a, a:focus, a:active, a:hover, a:visited {
    color: #528ecc;
    text-decoration: none;/* underline; */
    outline: 0 none;
}
#login_Name {
	font-size: 10pt;
	font-weight: bold;
	color: grey;
}
.logoutBt {
	background-color: #f8f8f8;
	border: 0px;
	float: right; 
	border-radius: 5px;
}
</style>
<script src="/js/jquery-1.12.4.min.js" type="text/javascript"></script>
<script src="/js/confirm.js?" type="text/javascript"></script>
<script src="/js/project-ui.js?" type="text/javascript"></script>
<script src="/js/netfunnel.js?fake=1703007064003" type="text/javascript" charset="utf-8"></script>

<!-- 드롭다운 토글 스크립트 -->
<script>
  $(document).ready(function () {
    $("#linkSite").click(function () {
      $(".layer-site").toggle();
    });
  });
</script>
<!-- 매뉴얼 새탭에서 PDF열기 -->
<script>
function openPDF(url) {
  // about:blank를 사용하여 새 탭 열기
  var newTab = window.open('about:blank', '_blank');
  
  // 새 탭에서 URL로 이동
  newTab.location.href = url;
}


$(function() {
	var jLANG = "KOR";
	//언어 선택
	$(".nav-header > span").click(function(){
		$(this).addClass("is-active").siblings().removeClass("is-active");
	});
//메뉴 컨트롤러
	$(".nav-control").click(function(){
		if($(this).hasClass("is-opened")){
			$(".wrap-container").addClass("nav-closed");
			$(this).removeClass("is-opened").addClass("is-closed").attr("title","메뉴열기");
		} else{
			$(".wrap-container").removeClass("nav-closed");
			$(this).removeClass("is-closed").addClass("is-opened").attr("title","메뉴닫기");
		}
	});
 
});


</script>
	
</head>
<body class="main">
	<div class="wrap-loader hidden"><span class="loading-helper"></span><div class="loader"></div><div class="loading-text">Loading</div></div>
	
	<div class="wrap-container">
		<div class="nav">
			<div class="nav-header">
				<span onclick="fnLang('KOR')" class="is-active">KOREAN</span>
				<span onclick="fnLang('ENG')" class="">ENGLISH</span>
			</div>
			<div class="nav-main">
			<table>
			<tr style="height: 10px;">
				<td id="login_Name" style="width: 70px;">${name }</td>
				<td><button onclick="logout()" class="logoutBt">로그아웃</button></td>
			</tr>
			</table>	
				<ul class="nav-menu">
					<li class="timeSet hidden"id="menu_sugang"><span onclick="location.href='/sugang/timeSet'" class="" style="color: #90213e;">수강신청 기간 설정</span></li>				
					<li id="menu_sugang"><span onclick="location.href='/sugang/sugang'" class="">수강신청</span></li>
					<li id="menu_basket"><span onclick="location.href='/sugang/cart'" class="">수강희망/관심과목 등록</span></li>
					<li class="has-child is-opened"><span class="">안내사항</span>
						<ul style="display: block;">
							<li id="menu_hakbu"><span onclick="location.href='/sugang/info'">수강신청 안내</span></li>
							<li><span onclick="location.href='/student/searchStNum'" id="menu_stdno" class="">학번 조회</span></li>
						</ul>
					</li>
					<li class="has-child is-opened"><span class="">마이페이지</span>
						<ul style="display: block;">
							<li id="menu_hakbu"><span onclick="location.href='/student/myInfo'">내 정보</span></li>
							<li><span onclick="location.href='/sugang/timeTable'" id="menu_stdno" class="">시간표</span></li>
						</ul>
					</li>
					
				</ul>
			</div>
			<div class="nav-footer">
				<div id="manual_KOR">
				<button type="button" class="btn-footer" onclick="window.open('about:blank').location.href='/resources/manual/manual_web.pdf'"><span id="manualPC">사용자 매뉴얼 (PC)</span><i class="sw-icon-download"></i></button>
				<button type="button" class="btn-footer" onclick="window.open('about:blank').location.href='/resources/manual/manual_mobile.pdf'"><span id="manualMO">사용자 매뉴얼 (모바일앱)</span><i class="sw-icon-download"></i></button>
				</div>
			
				<button type="button" class="btn-footer btn-main" id="linkSite"><span>관련사이트</span><i class="sw-icon-plus icon-plus"></i></button>
				<div class="layer-site" style="">
					<ul>
						<li><a href="http://portal.korea.ac.kr" target="_blank">KUPID</a></li>
						<li><a href="http://www.korea.ac.kr" target="_blank">홈페이지</a></li>
						<li><a href="http://registrar.korea.ac.kr" target="_blank">교육정보</a></li>
					</ul>
				</div>
				<div class="copy">Copyright © 2020 Korea University.<br>All Rights Reserved.</div>
			</div>
		</div>
		<div class="container">
			<div class="nav-control is-opened" title="메뉴닫기" style="top: 34px;"></div>
			<div class="header">
				<div class="is-left">
				<a href="/student/login"><img src="/img/karina.png" width="150px"></a>				
					<span class="title">수강신청 시스템</span>
				</div>
				
			</div>