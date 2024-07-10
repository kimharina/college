<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar_admin.jsp"%>
<nav class="nav-container">
	<div class="search-box">
		<input type="text" class="search-box-input" placeholder="Search" />		
			<button type="button" class="search-box-btn">
	 			<img src="/img/admin/search.png" alt="검색" class="search-box-btn-img">
				<i class="fa-solid fa-magnifying-glass"></i>
			</button>
	</div>

	<div class="notification">
		<div class="notification-icon">
			<span class="notification-badge">5</span> 
				<img src="/img/admin/alam.png" alt="Notification Icon" class="notification-alarm"> 
					<i class="fa-solid fa-bell"></i>
		</div>
		<div class="notification-icon">
			<span class="notification-badge1">9</span> 
				<img src="/img/admin/message.png" alt="Notification Icon" class="notification-message"> 
					<i class="fa-solid fa-envelope"></i>
		</div>
		<span id="notification-name">Admin</span>
	</div>
</nav>

<div class="container">
	<h4 class="my-4">관리자 모드</h4>
	<div class="row">
		<div class="col-lg-3">
			<div class="card monthly">
				<div class="card-body d-flex justify-content-between">
					<div>
						<p class="card-text mb-2">학과 관리</p>
						<button type="button" onclick="location.href='/student/department_regist'">학과 등록</button>
						<button type="button" onclick="location.href='/student/department_list'">학과 목록 보기</button>
					</div>
					<i class="fas fa-calendar"
						style="font-size: 30px; margin-top: 20px; color: #6c757d"></i>
				</div>
			</div>
		</div>
		<div class="col-lg-3">
			<div class="card annual">
				<div class="card-body d-flex justify-content-between">
					<div>
						<p class="card-text mb-2">교수 관리</p>
						<button type="button" onclick="location.href='/student/professor_regist'">교수
							등록</button>
						<button type="button" onclick="location.href='/student/professor_list'">교수
							목록 보기</button>
					</div>
					<i class="fa-solid fa-dollar-sign"
						style="font-size: 30px; margin-top: 20px; color: #6c757d"></i>
				</div>
			</div>
		</div>
		<div class="col-lg-3">
			<div class="card tasks">
				<div class="card-body d-flex justify-content-between">
					<div>
						<p class="card-text mb-2">학생 관리</p>
						<button type="button" onclick="location.href='/student/student_regist'">학생
							등록</button>
						<button type="button" onclick="location.href='/student/student_list'">학생
							목록 보기</button>
					</div>
					<i class="fa-solid fa-list-check"
						style="font-size: 30px; margin-top: 20px; color: #6c757d"></i>
				</div>
			</div>
		</div>
		<div class="col-lg-3">
			<div class="card requests">
				<div class="card-body d-flex justify-content-between">
					<div>
						<p class="card-text mb-2">강의 관리</p>
						<button type="button" onclick="location.href='/student/subject_regist'">강의
							등록</button>
						<button type="button" onclick="location.href='/student/subject_list'">강의
							목록 보기</button>
					</div>
					<i class="fa-solid fa-comments"
						style="font-size: 30px; margin-top: 20px; color: #6c757d"></i>
				</div>
			</div>
		</div>
	</div>
	<div class="row">
		<div class="col-lg-8">
			<div class="card-header h5">수강신청 시스템 만족도</div>
			<div class="card-body">
				<canvas id="myChart"></canvas>
			</div>
		</div>
		<div class="col-lg-4">
			<div class="card">
				<div class="card-header h5">Tasks</div>
				<ul class="list-group list-group-flush">
					<li class="list-group-item">모의 수강신청 기간</li>
					<li class="list-group-item">정정기간</li>
					<li class="list-group-item">수강 포기 기간</li>
				</ul>
			</div>
		</div>
	</div>
</div>
</body>
<style>
/* body부분 가운데로 */
.container {
	text-align: center; /* body의 텍스트를 중앙으로 정렬합니다. */
	width:1400px;
	display: inline-block; /* 가운데 정렬을 위해 inline-block 사용 */
}
/* 관리자모드 글씨*/
h4.my-4 {
	font-weight: bold; /* 글씨를 두껍게 만듭니다. */
	font-size: 1.5em; /* 글씨 크기를 조절합니다. */
	margin-top: 20px;
	margin-bottom: 20px;
}

/* ~관리 간격 조정 */
.card-text.mb-2 {
    margin-bottom: 7px; 
}

/* 상단 */
.nav-container {
	background-color: white;
	width: 100%;
	height: 60px;
	box-shadow: 0px 2px 2px 2px #eee;
	display: flex;
	justify-content: space-between;
}

/* 검색 */
.search-box {
	display: inline-flex;
	align-items: center;
	margin-left: 100px;
}

.search-box-input {
	padding: 5px;
	border-radius: 5px 0px 0px 5px;
	border: 1px solid lightgrey;
	width: 150px;
	transition: width 1s;
	height: 33px !important; /* !important 키워드 추가 */
}

.search-box-input:focus {
	width: 300px;
}

.search-box-btn {
	background-color: #343940;
	color: white;
	border: none;
	border-radius: 0px 5px 5px 0px;
	height: 33px;
	width: 40px;
}

/* 검색 버튼 내 이미지 스타일 */
.search-box-btn-img {
    width: 20px; /* 이미지 가로 크기 */
    height: 20px; /* 이미지 세로 크기 */
    margin-left:9px;
}

/* 우측 아이콘 */
.notification {
	display: flex;
	margin-right: 20px;
	align-items: center;
}

.notification-icon {
	font-size: x-large;
	margin-left: 60px;
	color: #808080;
	margin-bottom: 20px;
}

/* 알람 이미지 스타일 */
.notification-icon img.notification-alarm {
    width: 35px;  /* 알람 이미지의 너비 */
    height: 30px; /* 알람 이미지의 높이 */
    margin-top: 4px; 
    margin-right: 5px; /* 이미지와 뱃지 사이의 간격 */
}

/* 메세지 이미지 스타일 */
.notification-icon img.notification-message {
    width: 40px;  /* 메세지 이미지의 너비 */
    height: 40px; /* 메세지 이미지의 높이 */
    margin-bottom: -8px; 
    margin-right: 5px; /* 이미지와 뱃지 사이의 간격 */
}

.notification-badge { /* 알람 */
	position: relative;
	left: 18px;
	top: 18px;
	background-color: #DC3545;
	width: 20px;
	height: 20px;
	border-radius: 5px;
	display: flex;
	justify-content: center;
	align-items: center;
	color: white;
	font-size: small;
	font-weight: 600;
}

.notification-badge1 {	/* 메세지 */
	position: relative;
	left: 23px;
	top: 18px;
	background-color: #DC3545;
	width: 20px;
	height: 20px;
	border-radius: 5px;
	display: flex;
	justify-content: center;
	align-items: center;
	color: white;
	font-size: small;
	font-weight: 600;
}
#notification-name {
	margin-left: 40px;
	color: grey;
}
</style>

<!-- 관리자모드 -->
<style>
.row {
	display: flex;
	flex-wrap: wrap;
	justify-content: space-between;
}

.col-lg-3 {
	width: calc(25% - 30px);
	margin-bottom: 30px;
}

.card {
	height: 100%;
	border: 1px solid #dee2e6;
	border-radius: .25rem;
}

.card-body {
	position: relative;
}

.card-body::before {
	content: "";
	position: absolute;
	left: 0;
	top: 50%;
	transform: translateY(-50%);
	width: 3px;
	height: 70%;
	background-color: #e7d0df; /* 여기에 색상을 원하는 색으로 지정하세요. */
}

.card-body>div {
	margin-left: 10px; /* 선과 버튼 사이의 간격 조절 */
	position: relative;
	z-index: 1; /* 버튼이 선 위에 올라오도록 함 */
	padding: 10px; /* 적절한 패딩 값으로 조절하세요. */
	border-radius: 5px; /* 원하는 모양에 따라 조절하세요. */
}

/* 버튼 간격*/
button {
    margin-right: 10px; /* 오른쪽 여백을 10픽셀로 설정 */
}

/* 버튼 스타일 (필요에 따라 수정) */
.card-body button {
	background-color: #fff;
	color: #b6779e;
	border: 1px solid #e7d0df;
	padding: 5px 10px;
	cursor: pointer;
}

/*tasks css*/
/* 카드에 테두리 추가 */
.card {
	border: 1px solid #dee2e6;
	border-radius: .25rem;
	box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); /* 그림자 추가 */
}

.col-lg-4 {
	width: 190px;
	margin-right: 5px;
}

/* 리스트 그룹의 각 아이템에 테두리 추가 */
.list-group-item {
	border: 1px solid #dee2e6;
	border-radius: 0; /* 리스트 그룹 아이템의 모서리 둥글기 제거 */
	margin-left: 15px; /* 선과 버튼 사이의 간격 조절 */
	margin-right: 15px; /* 선과 버튼 사이의 간격 조절 */
	margin-bottom: 7px; /* 선과 버튼 사이의 간격 조절 */
	position: relative;
	z-index: 1; /* 버튼이 선 위에 올라오도록 함 */
	padding: 10px; /* 적절한 패딩 값으로 조절하세요. */
	border-radius: 5px; /* 원하는 모양에 따라 조절하세요. */
}

.card-header.h5 {
	font-weight: bold; /* 글씨 두껍게 */
	margin-left: 10px;
	margin-top: 10px; /* 위 여백 10px */
	margin-bottom: 10px;
}

/* 차트 크기 */
.card-header.h5 {
    font-size: 20px; /* 텍스트 크기를 24픽셀로 설정, 원하는 크기로 조절 가능 */
}

#myChart {
    width: 100%; /* 부모 요소의 100% 크기로 설정 */
    height: 400px; /* 높이를 원하는 크기로 설정 */
}
</style>


<!-- chart js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
	var ctx = document.getElementById("myChart").getContext("2d");
	var myChart = new Chart(ctx,
			{
				type : "line",
				data : {
					labels : ["매우 불만족.", "불만족.", "보통.", "만족.", "매우 만족."],
					datasets : [ {
						label : "총 응답 102개",
						data : [7, 29, 34, 12, 3],
						backgroundColor : "#e7d0df",
						borderColor : "#3e3f47",
						borderWidth : 1,
						fill : true,
						tension : 0.2,
					}, ],
				},
				options : {
					scales : {
						y : {
							beginAtZero : true,
						},
					},
				},
			});
</script>
</html>