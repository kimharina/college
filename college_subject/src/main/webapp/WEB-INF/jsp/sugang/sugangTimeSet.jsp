<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar_SLogin.jsp"%>
<script src="https://code.jquery.com/jquery-latest.js"></script>
<div id="contents" class="contents">
	<div style="width: 60%">
			<div class="modal_content">
				<div class="mTitle">
					<h1>수강신청 기간 설정</h1>
				</div>
				<br>
	<!-- 수강신청 시작, 마감 -->
			<div id="list_jpg">
			    <div class="jpg">></div>
				<div>&nbsp;시작 시간 설정</div>
			</div>
				<div class="mContent">
					<table class="tbl-detail">
						<colgroup>
							<col width="10%">
							<col width="10%">
							<col width="35%">
							<col width="35%">
						</colgroup>
						<thead>
							<tr>
								<th></th>
								<th colspan="3">시간</th>
							</tr>
						</thead>
						<tbody class="th-center td-center">
							<tr>
							<th rowspan="4">시작시간</th>
								<th>년도</th>
								<td colspan="2"><select id="yearSelect"></select></td>
							</tr>
							<tr>
								<th>월</th>
								<td colspan="2"><select id="monthSelect"></select></td>
							</tr>
							<tr>
								<th>일</th>
								<td colspan="2"><select id="daySelect"></select></td>
							</tr>
							<tr>
								<th>시간(시/분)</th>
								<td><select id="hourSelect"></select></td>
								<td><select id="minSelect"></select></td>
							</tr>

							<tr>
								<th rowspan="4">마감시간</th>
								<th>년도</th>
								<td colspan="2"><select id="endYearSelect"></select></td>
							</tr>
							<tr>
								<th>월</th>
								<td colspan="2"><select id="endMonthSelect"></select></td>
							</tr>
							<tr>
								<th>일</th>
								<td colspan="2"><select id="endDaySelect"></select></td>
							</tr>
							<tr>
								<th>시간(시/분)</th>
								<td><select id="endHourSelect"></select></td>
								<td><select id="endMinSelect"></select></td>
							</tr>
	
						</tbody>
					</table>
				</div><br>
				<div align="center"><button type="button" class="search">확인</button></div>

				
				
			</div>
	</div>
</div>
</body>
</html>
	<script>
        // 현재 년월 구하기
        var currentYear = new Date().getFullYear();
        var currentMonth = new Date().getMonth() + 1; // getMonth()는 0부터 시작하므로 +1
        // select 요소 가져오기
        var yearSelect = document.getElementById('yearSelect');
        var monthSelect = document.getElementById('monthSelect');
        var daySelect = document.getElementById('daySelect');
        var hourSelect = document.getElementById('hourSelect');
        var minSelect = document.getElementById('minSelect');
        
        var endYearSelect = document.getElementById('endYearSelect');
        var endMonthSelect = document.getElementById('endMonthSelect');
        var endDaySelect = document.getElementById('endDaySelect');
        var endHourSelect = document.getElementById('endHourSelect');
        var endMinSelect = document.getElementById('endMinSelect');

     // 년도 select
        for (var year = 2020; year <= 2040; year++) {
            // 시작 시간의 option 요소 생성
            var optionStart = document.createElement('option');
            optionStart.value = year;
            optionStart.text = year;
            // 현재 년도인 경우 선택 상태로 설정
            if (year === currentYear) {
                optionStart.selected = true;
            }
            yearSelect.add(optionStart);

            // 마감 시간의 option 요소 생성
            var optionEnd = document.createElement('option');
            optionEnd.value = year;
            optionEnd.text = year;
            // 현재 년도인 경우 선택 상태로 설정
            if (year === currentYear) {
                optionEnd.selected = true;
            }
            endYearSelect.add(optionEnd);
        }

        //월select
        for (var month = 1; month <= 12; month++) {
            var option = document.createElement('option');
            option.value = month;
            option.text = month;
            // 현재 년도인 경우 선택 상태로 설정
            if (month === currentMonth) {
                option.selected = true;
            }
            monthSelect.add(option);
            
            // 마감 시간의 option 요소 생성
            var optionEnd = document.createElement('option');
            optionEnd.value = month;
            optionEnd.text = month;
            // 현재 년도인 경우 선택 상태로 설정
            if (month === currentMonth) {
                optionEnd.selected = true;
            }
            endMonthSelect.add(optionEnd);
        }
        //일select
        for (var day = 1; day <= 31; day++) {
            var option = document.createElement('option');
            option.value = day;
            option.text = day;
            daySelect.add(option);
         	// 마감 시간의 option 요소 생성
            var optionEnd = document.createElement('option');
            optionEnd.value = day;
            optionEnd.text = day;
            endDaySelect.add(optionEnd);            
            
        }
        //시select
        for (var hour =0; hour <= 24; hour++) {
            var option = document.createElement('option');
            option.value = hour;
            option.text = hour;
            hourSelect.add(option);
         	// 마감 시간의 option 요소 생성
            var optionEnd = document.createElement('option');
            optionEnd.value = hour;
            optionEnd.text = hour;
            endHourSelect.add(optionEnd);
        }
        //분select
        for (var min = 0; min <= 59; min++) {
            var option = document.createElement('option');
            option.value = min;
            option.text = min;
            minSelect.add(option);
         	// 마감 시간의 option 요소 생성
            var optionEnd = document.createElement('option');
            optionEnd.value = min;
            optionEnd.text = min;
            endMinSelect.add(optionEnd);
        }
        
    </script>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script>
	$(document).ready(function() {				
		$('.search').on('click', function() {
			var time = {
					// select 요소 가져오기
					yearSelect: $("#yearSelect").val(),
					monthSelect: $("#monthSelect").val(),
					daySelect: $("#daySelect").val(),
					hourSelect: $("#hourSelect").val(),
					minSelect: $("#minSelect").val(),
					endYearSelect: $("#endYearSelect").val(),
					endMonthSelect: $("#endMonthSelect").val(),
					endDaySelect: $("#endDaySelect").val(),
					endHourSelect: $("#endHourSelect").val(),
					endMinSelect: $("#endMinSelect").val()
			}
	            $.ajax({	
	                type: "POST",
	                url: "/sugang/timeSet",
	                contentType: "text",
	                data: JSON.stringify(time),
	                headers: {
			            'Content-Type': 'application/json',
			            'Authorization': localStorage.getItem('Authorization'),
			        },
	                success: function(data) {
	                    console.log(data);
	                    alert("시간 설정 완료");
		            },
		            error: function (xhr, status, error) {
		                if (xhr.status === 401) {
		                    // Unauthorized 상태
		                    localStorage.removeItem("Authorization");
		                    alert("다시 로그인해주세요.");
		                    window.location.href = '/student/login';
		                } else {
		                    // 다른 오류 처리
		                    console.error("데이터 전송 중 오류가 발생했습니다. 상태: " + status + ", 오류: " + error);
		                }
		            }
		        });
		    });
		
		});

</script>
<style>
	.search {
		height: 30px;
		width: 50%;
		font-size: 10pt;
		background-color: #a20131;
		color: #fff;
		border-radius: 5px;
		cursor: pointer;
		margin-top: 5px;
		float: center;
		
	}
	.jpg {
		float: left;
		width:  20px;
		height: 20px;
		line-height:20px;
		background-color: #a20131;
		color: #fff;
		text-align: center;
		font-size: 20px;
		margin-bottom: 8px;
		margin-left: 8px;
	}


</style>