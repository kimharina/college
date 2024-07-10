<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ include file="../sideBar_SLogin.jsp"%>

<body>
	<div id="contents" class="contents">
		<div id="head_bar">
			<div class="one">2022년도 1학기</div>

			<div class="ttt">성명</div>
			<div class="ttt_1" id="name">${name}</div>
			<div class="ttt_1" id="student_No">${student_No}</div>

			<div class="ttt">차시</div>
			<div class="ttt_1">2차시</div>
		</div>
<div class="form-search">
		<form id="searchForm">
			<table>
				<colgroup>
					<col width="60px">
					<col width="80px">
					<col width="80px">
					<col width="80px">
					<col width="80px">
					<col width="220px">
					<col width="80px">
					<col width="120px">
					<col>
				</colgroup>
				<tbody>
					<tr>
						<th>년도</th>
						<td><input type="text" name="pYear" id="pYear" value="2024"
							maxlength="4" style="ime-mode: disabled"></td>
						<th>학년</th>
						<td><select name="grade" id="grade">
								<option value="" disabled selected style="display: none;"></option>
								<option value="1학년">1학년</option>
								<option value="2학년">2학년</option>
								<option value="3학년">3학년</option>
								<option value="4학년">4학년</option>
						</select></td>
						<th class="isu">이수구분</th>
						<td class="isu" colspan="2">
							<div class="cols">
								<select name="subject_Type" id="subject_Type" onchange="typeSelect()">
									<option value="" disabled selected style="display: none;">이수구분을 선택하세요</option>
									<option value="전공필수">전공필수</option>
									<option value="전공선택">전공선택</option>
									<option value="교양과목">교양과목</option>
								</select> <select name="department_Name" id="department_Name"  style="display: block;">
									<option value="" disabled selected style="display: none;">학과를 선택하세요</option>
									<option value="국어국문학과">국어국문학과</option>
									<option value="국제개발협력학과">국제개발협력학과</option>
									<option value="미디어소프트웨어학과">미디어소프트웨어학과</option>
									<option value="뷰티디자인학과">뷰티디자인학과</option>
									<option value="사회복지학과">사회복지학과</option>
									<option value="연극영화학과">연극영화학과</option>
									<option value="영어영문학과">영어영문학과</option>
									<option value="유아교육과">유아교육과</option>
									<option value="음악학과">음악학과</option>
									<option value="정보통신학과">정보통신학과</option>
									<option value="중어중문학과">중어중문학과</option>
									<option value="체육교육과">체육교육과</option>
									<option value="컴퓨터공학과">컴퓨터공학과</option>
									<option value="행정학과">행정학과</option>
								</select>

							</div>
						</td>
					</tr>
					<tr>
						<th>학점</th>
						<td>
							<!-- <input type="text" name="subject_Point" id="subject_Point" maxlength="3" style="ime-mode:disabled"> -->
							<select name="subject_Point" id="subject_Point">
								<option value="" disabled selected style="display: none;"></option>
								<option value="3">3</option>
								<option value="2">2</option>
								<option value="1">1</option>
							</select>
						</td>
						<th>요일</th>
						<td><select name="day" id="day">
								<option value="">전체--</option>
								<option value="월요일">월</option>
								<option value="화요일">화</option>
								<option value="수요일">수</option>
								<option value="목요일">목</option>
								<option value="금요일">금</option>
						</select></td>
						<th>시간</th>
						<td>
							<div class="cols">
								<select id="start_Time_Output" name="start_Time_Output">
									<option value="">전체--</option>

									<option>9:00</option>

									<option>9:30</option>

									<option>10:00</option>

									<option>10:30</option>

									<option>11:00</option>

									<option>11:30</option>

									<option>12:00</option>

									<option>12:30</option>

									<option>13:00</option>

									<option>13:30</option>

									<option>14:00</option>

									<option>14:30</option>

									<option>15:00</option>

									<option>15:30</option>

									<option>16:00</option>

									<option>16:30</option>

									<option>17:00</option>

									<option>17:30</option>

									<option>18:00</option>

									<option>18:30</option>

									<option>19:00</option>

									<option>19:30</option>

									<option>20:00</option>

									<option>20:30</option>

								</select> <span class="unit">~</span> 
								
								<select id="end_Time_Output" name="end_Time_Output">
									<option value="">전체--</option>

									<option>9:00</option>

									<option>9:30</option>

									<option>10:00</option>

									<option>10:30</option>

									<option>11:00</option>

									<option>11:30</option>

									<option>12:00</option>

									<option>12:30</option>

									<option>13:00</option>

									<option>13:30</option>

									<option>14:00</option>

									<option>14:30</option>

									<option>15:00</option>

									<option>15:30</option>

									<option>16:00</option>

									<option>16:30</option>

									<option>17:00</option>

									<option>17:30</option>

									<option>18:00</option>

									<option>18:30</option>

									<option>19:00</option>

									<option>19:30</option>

									<option>20:00</option>

									<option>20:30</option>

								</select>
								<button type="button" class="btnGyosi" onclick="fnViewTime()">교시확인표</button>

							</div>
						</td>
						<th>담당교수</th>
						<td><input type="text" name="professor_Name" id="professor_Name" style="ime-mode: active;"></td>
					</tr>
					<tr>
						<th>과목코드</th>
						<td><input style="ime-mode: disabled;" type="text"
							id="subject_No" name="subject_No" maxlength="7"></td>
						<th></th>
						<td></td>
						<th>교과목명</th>
						<td colspan="3"><input type="text" name="subject_Name" id="subject_Name"></td>
						<td class="search">
							<button type="button" id="btnSearch" class="btn-sub">조회</button>
							<button type="button" id="btnReset" onclick="javascript:fnReset()">초기화</button>
						</td>
					</tr>
				</tbody>
			</table>

		</form>
		<!-- <div id="warning" style="display: inline-flex;color:#fff;text-align:center;height:30px;width:80%" class="is-green"></div> -->
	</div>
	<div class="info-box" style="padding: 5px 25px">
		<div id="legendKOR" style="display: block;" class="highlight">
			<ul class="list-dot">
				<li><span class="txt-red">과목코드</span> 검색시<span class="txt-blue"> 정확히 </span>입력해야 합니다.</li>
				<li>과목코드 클릭시 강의계획안 조회가 가능합니다.</li>
				<li><span class="txt-blue"> 시작 </span> 클릭시 시간순 정렬이 가능합니다.</li>
			</ul>
		</div>
	</div>
		<div id=list_head style="max-height: 500px; overflow-y: auto;">
			<table border="1" id="sub_list">
			<thead>
				<tr class="tr">
					<th class="th" style="width: 7%;">과목코드</th>
					<th class="th" style="width: 10%;">이수구분</th>
					<th class="th" style="width: 20%;">교과목명</th>
					<th class="th" style="width: 5%;">학년</th>
					<th class="th" style="width: 3%;">학점</th>
					<th class="th" style="width: 5%;">요일</th>
					<th class="th" style="width: 5%;">
						<a href="#" onclick="array()">시작 <img alt="array" src="/img/array.svg"></a>
						<input type="hidden" id="Order" name="Order" value="Asc">
					</th>
					<th class="th" style="width: 3%;">~</th>
					<th class="th" style="width: 5%;">종료</th>
					<th class="th" style="width: 10%;">개설학과</th>
					<th class="th" style="width: 7%;">교수</th>
					<th class="th" style="width: 7%;">수강시간</th>
					<th class="th" style="width: 7%;">인원제한</th>
					<th class="th" style="width: 7%;">저장</th>
				</tr>
				</thead>
				<tbody id = "ajaxresult">
						<td valign="top" colspan="15" class="th">조회 조건 선택 후 조회 버튼을 클릭하세요.</td>
				</tbody>
				
			</table>

		</div>


		<div id="list_jpg">
		    <div class="jpg">></div>
		    <div>수강희망/관심과목 내역
		        <form id="submitForm">				
		            <button type="submit" class="btn">신청</button>
		        </form>
		    </div>
		</div>

		<div id="list_head">
	    <table border="1" id="sub_list">
	        <thead>
	            <tr class="tr" id="chk_append">
					<th class="th" style="width: 7%;">과목코드</th>
					<th class="th" style="width: 10%;">이수구분</th>
					<th class="th" style="width: 20%;">교과목명</th>
					<th class="th" style="width: 5%;">학년</th>
					<th class="th" style="width: 3%;">학점</th>
					<th class="th" style="width: 5%;">요일</th>
					<th class="th" style="width: 5%;">시작</th>
					<th class="th" style="width: 3%;">~</th>
					<th class="th" style="width: 5%;">종료</th>
					<th class="th" style="width: 10%;">개설학과</th>
					<th class="th" style="width: 7%;">교수</th>
					<th class="th" style="width: 7%;">수강시간</th>
					<th class="th" style="width: 7%;">인원제한</th>
					<th class="th" style="width: 7%;">저장</th>
	            </tr>
	        </thead>
	        <tbody id="temp"></tbody>
	    </table>
		</div>
<hr style="border: 0.5px solid #808080;">
	
	<div id="list_jpg" style="margin-top: 20px;">
	    <div class="jpg1">></div>
	    	<div>수강신청 내역
	    </div>
	</div>

	<div id="list_head">
    <table border="1" id="cart_list">
        <thead>
            <tr class="tr" id="chk_append">
				<th class="th" style="width: 7%;">과목코드</th>
				<th class="th" style="width: 10%;">이수구분</th>
				<th class="th" style="width: 20%;">교과목명</th>
				<th class="th" style="width: 5%;">학년</th>
				<th class="th" style="width: 3%;">학점</th>
				<th class="th" style="width: 5%;">요일</th>
				<th class="th" style="width: 5%;">시작</th>
				<th class="th" style="width: 3%;">~</th>
				<th class="th" style="width: 5%;">종료</th>
				<th class="th" style="width: 10%;">개설학과</th>
				<th class="th" style="width: 7%;">교수</th>
				<th class="th" style="width: 7%;">수강시간</th>
				<th class="th" style="width: 7%;">인원제한</th>
				<th class="th" style="width: 7%;">
					<form id="submitForm">				
			            <button type="submit" class="btn_deleteAll">전체 삭제</button>
			        </form>
		        </th>
            </tr>
        </thead>
        <tbody id="cart_result"></tbody>
    </table>
</div>
				
		
</body>
</html>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script src="https://code.jquery.com/jquery-latest.js"></script>
<!-- Bootstrap JavaScript (Popper.js와 함께) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
<script>
//검색 버튼 클릭 이벤트 핸들러

$("#btnSearch").on("click", function () {
    // 검색 조건 수집
    var searchData = {
        grade: $("#grade").val(),
        subject_Type: $("#subject_Type").val(),
        department_Name: $("#department_Name").val(),
        subject_Point: $("#subject_Point").val(),
        day: $("#day").val(),
        start_Time_Output: $("#start_Time_Output").val(),
        end_Time_Output: $("#end_Time_Output").val(),
        professor_Name: $("#professor_Name").val(),
        subject_No: $("#subject_No").val(),
        subject_Name: $("#subject_Name").val()
    };
	
    // Ajax를 이용해 서버로 데이터 전송
    $.ajax({
        type: "POST",
        url: "/sugang/cart",
        data: JSON.stringify(searchData),
        headers: {
            'Content-Type': 'application/json',
            'Authorization': localStorage.getItem('Authorization'),
        },
        success: function (data) {
            console.log("성공");
            console.log(data);

            // data가 배열이 아니면 배열로 변환
            var dataArray = Array.isArray(data) ? data : [data];

            // 결과를 담을 변수
            var tableHTML = '';
                // 여기에 필요한 헤더 등을 추가

                // 결과 데이터를 테이블에 추가
                dataArray.forEach(function (subjects) {
                	tableHTML += '<tr>';
                    tableHTML += '<td class="th" style="width: 7%;"><a href="#" onclick="openPopup(\'detail?subject_No=' + subjects.subject_No + '\')">' + subjects.subject_No + '</a></td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 10%;">' + subjects.subject_Type + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th"style="width: 20%;">' + subjects.subject_Name + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 5%;">' + subjects.grade + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 3%;">' + subjects.subject_Point + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 5%;">' + subjects.day + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
					tableHTML += '<td class="th" style="width: 5%;">' + subjects.start_Time_Output + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
					tableHTML += '<td class="th" style="width: 3%;"> ~ </td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 5%;">' + subjects.end_Time_Output + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 10%;">' + subjects.department_Name + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 7%;">' + subjects.professor_Name + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 7%;">' + subjects.study_Time + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 7%;">' + subjects.student_Count + '</td>';
                    tableHTML += '<td class="hidden-comma">,</td>';
                    tableHTML += '<td class="th" style="width: 7%;"><input type="button" value="저장" class="list_btn" /></td>';
                    // 나머지 필드도 동일하게 추가
                    tableHTML += '</tr>';
                });

            // 결과를 HTML에 반영
            $('#ajaxresult').html(tableHTML);
        },
        error: function (xhr, status, error) {
            // 에러 처리
            console.error("데이터 전송 중 오류가 발생했습니다. Status: " + status + ", Error: " + error);
        }
    });
});

	function fnReset() { //초기화 기능
		$("#pYear").val("2024");
		$("#grade").val("2W");
		$("#subject_Point").val("");
		$("#day").val(""); 					//day, start_Time_Output, end_Time_Output 여기 전체--라고 표시를 하려면 값을 비워둬야한다
		$("#start_Time_Output").val("");
		$("#end_Time_Output").val("");
		$("#professor_Name").val("");
		$("#subject_No").val("");
		$("#subject_Name").val("");
		$("#subject_Type").val("");
		$("#department_Name").val("");
		$("#professor_Name,#subject_No,#department_Name,#subject_Name").val('');
		
		 $("#btnSearch").click();

	}
    // 팝업 열기 함수
    function openPopup(url) {
        window.open(url, 'popup', 'width=600,height=1000');
        return false; // 링크 클릭 시 기본 동작 방지
    }

    $(document).ready(function () {
        // extractRowData 함수 정의
        function extractRowData(row) {
            var rowData = '';
            row.find('td').each(function () {
                rowData += $(this).text().trim();
            });
            return rowData;
        }

        var savedData = []; // 저장된 데이터를 담을 배열

        $('#ajaxresult').on('click', '.list_btn', function () {
            var tr = $(this).closest('tr'); // 저장 버튼을 누른 행을 찾습니다.
            var data = extractRowData(tr); // 행 데이터를 추출합니다.

            var row = $(this).closest('tr'); // 클릭된 버튼이 속한 행을 찾습니다.

            if (isAlreadySaved(data)) {
                alert("이미 신청한 과목(동일과목) 입니다!");
            } else {
                savedData.push(data); // 배열에 저장된 데이터 추가

                var clonedRow = tr.clone(); // 행을 복제합니다.
                clonedRow.find('.list_btn').remove(); // 저장 버튼은 필요 없으므로 제거합니다.

                // 취소 버튼으로 대체합니다.
                clonedRow.find('td:last').html('<input type="button" value="취소" class="delete_btn" />');

                // temp 영역에 복제된 행을 추가합니다.
                $('#temp').append('<tr>' + clonedRow.html() + '</tr>');
            }
        });

    $(document).on("click", ".delete_btn", function() {
        var tr = $(this).closest('tr');
        var dataToRemove = extractRowData(tr);
        
        removeSavedData(dataToRemove);
        tr.remove();
    });

    $(".btn").click(function() {
        var allDataToBeSent = [];

        // 행 데이터를 모두 가져와서 저장
        $('#temp tr').each(function() {
            var rowData = extractRowData($(this));
            allDataToBeSent.push(rowData);
        });
        
        var dataToBeSent = {
           savedData: allDataToBeSent
        };
         // 배열을 문자열로 결합
            var combinedString = savedData.join(', ');

            // 콤마(,)를 기준으로 문자열을 배열로 변환
            var parsedData = combinedString.split(',');

            // 숫자로 변환할 요소의 인덱스
            var indexesToConvert = [0, 4]; // 여기서는 0번째와 4번째 요소를 정수형으로 변환하려고 합니다.

            // 요소를 정수로 변환
            indexesToConvert.forEach(function(index) {
                parsedData[index] = parseInt(parsedData[index]);
            });

         // parsedData 배열 내에서 숫자 데이터를 정수로 변환
            for (var i = 0; i < parsedData.length; i++) {
                if (!isNaN(parsedData[i])) { // 숫자인지 확인
                    parsedData[i] = parseInt(parsedData[i]);
                }
            }
            console.log("parsedData:", parsedData);
         // subject_nos를 저장할 배열
            // 특정한 패턴으로 인덱스가 증가하는 경우
         var subjectNos = [];
         var patternSize = 14; // 패턴의 크기
         
         // 반복문을 사용하여 값을 동적으로 가져오기
         for (var i = 0; i < parsedData.length; i += patternSize) {
             if (parsedData[i] !== undefined) {
                 subjectNos.push(parsedData[i]);
             }
             // 추가적인 작업 수행 가능
         }
         
         // 중복 제거 로직 추가
         subjectNos = subjectNos.filter((value, index, self) => {
             return self.indexOf(value) === index;
         });
         
         console.log("subject_No:", subjectNos);

         // 데이터를 서버로 전송
         $.ajax({
             type: "POST",
             url: "/sugang/save-data-endpoint",
             contentType: "application/json",
             dataType: 'text',
             data: JSON.stringify({ 
                "subject_No": subjectNos
             }),
             headers: {
                 'Content-Type': 'application/json',
                 'Authorization': localStorage.getItem('Authorization'),
             },
             
             // 전체 데이터를 전송
             success: function(response) {
                 console.log("데이터가 성공적으로 서버에 전송되었습니다.");
                 console.log(response);
                 if(response.includes("같은 시간에 이미 수업이 있습니다.")) {
                     alert(response);
                 } else if(response.includes("신청 실패")) {
                	 alert(response); // 서버로부터 받은 응답을 알림창으로 표시
                 } else if(response.includes("장바구니 등록 완료!")) {
                	 alert(response); // 서버로부터 받은 응답을 알림창으로 표시
                 }
             },
             error: function(error,status) {
                console.error("데이터 전송 중 오류가 발생했습니다. Status: " + status + ", Error: " + error);
             }
         });


        // 저장된 데이터를 초기화
        /* savedData = []; */
        $('#temp').empty();
    });

    function saveData(data) {
        savedData.push(data);
    }

    function removeSavedData(data) {
        savedData = savedData.filter(item => !compareRows(item, data));
    }

    function isAlreadySaved(data) {
        return savedData.some(item => compareRows(item, data));
    }

    function compareRows(row1, row2) {
        return row1 === row2;
    }

 // 클릭된 행의 모든 데이터를 배열로 추출하는 함수
    function extractRowDataArray(row) {
        var rowDataArray = [];
        row.find('td').each(function () {
            rowDataArray.push($(this).text().trim());
        });
        return rowDataArray;
    }
});

    var sortOrder = "Desc"; // 초기 정렬 방식
    function array() {
        // 클릭할 때마다 sortOrder 변경
        sortOrder = sortOrder === "Asc" ? "Desc" : "Asc";
        // 현재 정렬 방식을 hidden input에 설정
        document.getElementById("Order").value = sortOrder;
       	console.log("sortOrder: ",sortOrder);
     
        // AJAX를 이용해 서버로 데이터 전송
        $.ajax({
            type: "POST",
            url: "/sugang/order", 
            headers: {
                'Content-Type': 'application/json',
                'Authorization': localStorage.getItem('Authorization'),
            },
            data: JSON.stringify({
                grade: $("#grade").val(),
                subject_Type: $("#subject_Type").val(),
                department_Name: $("#department_Name").val(),
                subject_Point: $("#subject_Point").val(),
                day: $("#day").val(),
                start_Time_Output: $("#start_Time_Output").val(),
                end_Time_Output: $("#end_Time_Output").val(),
                professor_Name: $("#professor_Name").val(),
                subject_No: $("#subject_No").val(),
                subject_Name: $("#subject_Name").val(),
            	Order: sortOrder
            }),
            success: function(response) {
                console.log("서버 응답: ", response);
                // data가 배열이 아니면 배열로 변환
                var dataArray = Array.isArray(response) ? response : [response];

                // 결과를 담을 변수
                var tableHTML = '';
                    // 여기에 필요한 헤더 등을 추가

                    // 결과 데이터를 테이블에 추가
                    dataArray.forEach(function (subjects) {
                    	tableHTML += '<tr>';
                        tableHTML += '<td class="th" style="width: 7%;"><a href="#" onclick="openPopup(\'detail?subject_No=' + subjects.subject_No + '\')">' + subjects.subject_No + '</a></td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 10%;">' + subjects.subject_Type + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th"style="width: 25%;">' + subjects.subject_Name + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 5%;">' + subjects.grade + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 3%;">' + subjects.subject_Point + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 5%;">' + subjects.day + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
    					tableHTML += '<td class="th" style="width: 5%;">' + subjects.start_Time_Output + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
    					tableHTML += '<td class="th" style="width: 3%;"> ~ </td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 5%;">' + subjects.end_Time_Output + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 15%;">' + subjects.department_Name + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 7%;">' + subjects.professor_Name + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 7%;">' + subjects.study_Time + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 7%;">' + subjects.student_Count + '</td>';
                        tableHTML += '<td class="hidden-comma">,</td>';
                        tableHTML += '<td class="th" style="width: 7%;"><input type="button" value="저장" class="list_btn" /></td>';
                        // 나머지 필드도 동일하게 추가
                        tableHTML += '</tr>';
                    });

                // 결과를 HTML에 반영
                $('#ajaxresult').html(tableHTML);
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
    };  

function typeSelect() {
	var subject_TypeSelect = document.getElementById("subject_Type");
	var department_NameSelect = document.getElementById("department_Name");
						
	if (subject_TypeSelect.value === "교양과목") {
	// 교양 선택 시 department_Name 숨기기
	department_NameSelect.style.display = "none";
		td.isu.colspan = "1";
	} else {
		// 다른 이수구분일 경우 department_Name 보이기
		department_NameSelect.style.display = "block";
	}
						
	}
//수강신청 내역
$.ajax({
    url: "/sugang/cart_show",  
    type: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': localStorage.getItem('Authorization'),
    },
    data: JSON.stringify({ subject_No: 'subject_No' }), // 데이터 추가
    success: function(data) {
        var dataArray = Array.isArray(data) ? data : [data];
        var tableHTML = '<table border="1" id="cart_list">'; //하단에 리스트 나타내기
        
        dataArray.forEach(function (carts) { 
            // CartDTO의 필드에 따라서 td에 데이터 삽입
            tableHTML += '<tr class="tr">';
    		tableHTML += '<td class="th" style="width: 10%;">' + carts.subject_No + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 10%;">' + carts.subject_Type + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th"style="width: 20%;">' + carts.subject_Name + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 5%;">' + carts.grade + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 3%;">' + carts.subject_Point + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 5%;">' + carts.day + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
			tableHTML += '<td class="th" style="width: 5%;">' + carts.start_Time_Output + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
			tableHTML += '<td class="th" style="width: 3%;"> ~ </td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 5%;">' + carts.end_Time_Output + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 10%;">' + carts.department_Name + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 7%;">' + carts.professor_Name + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 7%;">' + carts.study_Time + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 7%;">' + carts.student_Count + '</td>';
            tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 5%;"><input type="button" value="취소" class="delete_btn" data-subject-no="' + carts.subject_No + '" /></td>';
            // 나머지 필드도 동일하게 추가
            tableHTML += '</tr>';
        });

        tableHTML += '</table>';
        $('#cart_result').html(tableHTML);
    },
    error: function(error) {
        console.error('Error getting cart data from the server:', error);
    }
});

//수강신청 내역 - (2) 취소하기
$(document).on("click", ".delete_btn", function() {
  var tr = $(this).closest('tr');
  var subjectNoToDelete = tr.find('.subject_no_column').text().trim(); // subject_no를 찾는 로직 추가

  // 행 삭제
  tr.remove();

  // 서버에서 데이터 삭제
  $.ajax({
      url: "/sugang/cart_show_delete",
      type: 'POST',
      headers: {
          'Content-Type': 'application/json',
          'Authorization': localStorage.getItem('Authorization'),
      },
      data: JSON.stringify({ subject_No: parseInt(tr.find('.th').eq(0).text().trim()) }), // 첫 번째 td에서 subject_No 값을 얻어와 정수로 변환
      success: function(response) {
          console.log("데이터가 성공적으로 삭제되었습니다.");
          console.log(response);
          alert("수강신청 취소 완료!");
          location.reload(); // 페이지 새로고침
      },
      error: function(error, status) {
          console.error("데이터 삭제 중 오류가 발생했습니다. Status: " + status + ", Error: " + error);
      }
  });
});

function extractRowData(tr) { //특정 <tr>에 대한 데이터가 추출된 객체로 얻을 수 있음
  var rowData = {};
  tr.find('td').each(function(index, el) {
      var columnName = $(el).attr('class'); // 각 칼럼의 class를 가져와서 columnName으로 사용
      rowData[columnName] = $(el).text().trim();
  });
  return rowData;
}

function removeSavedData(data) {
  // 여기에서는 서버에서 삭제하므로 클라이언트 측에서는 따로 작업하지 않음
}
//수강신청 내역 - (3) 전체 삭제
$(document).on("click", ".btn_deleteAll", function () {
    var allRows = $('#cart_list tbody tr');  // 테이블의 모든 행 가져오기

    var dataArray = [];

    // 테이블의 각 행 데이터를 배열에 추가
    allRows.each(function (index, row) {
        var rowDataArray = extractRowDataArray($(row));
        dataArray.push(rowDataArray);
    });

    // 중복된 행 제거
    dataArray = dataArray.filter((value, index, self) => {
        return self.findIndex(item => compareRows(item, value)) === index;
    });

    console.log("전송할 데이터:", dataArray);

    // subject_no를 int로 변환하여 subjectNos 배열에 담기
    var subjectNos = dataArray.map(item => parseInt(item[0]));
    console.log("subjectNos:", subjectNos);

    // 서버로 데이터 전송
    $.ajax({
        type: "POST",
        url: "/sugang/cart_deleteAll",
        contentType: "application/json",
        data: JSON.stringify({ subject_No: subjectNos }),  // 전체 행 데이터를 배열로 묶어서 전송
        headers: {
            'Content-Type': 'application/json',
            'Authorization': localStorage.getItem('Authorization'),
        },
        success: function (response) {
            console.log("장바구니 전체 삭제완료!");
            console.log(response);
            alert("장바구니 전체 삭제완료!");
            $('#cart_result').empty();
        },
        error: function (error) {
            console.error("장바구니 삭제중 오류가 발생했습니다.", error);
        }
    });

    // 클릭된 행의 모든 데이터를 배열로 추출하는 함수
    function extractRowDataArray(row) {
        var rowDataArray = [];
        row.find('td').each(function () {
            rowDataArray.push($(this).text().trim());
        });
        return rowDataArray;
    }

    // 행 비교 함수
    function compareRows(row1, row2) {
        return JSON.stringify(row1) === JSON.stringify(row2);
    }
});
</script>

<style>
#myModal {
  position:absolute;
  width:100%;
  height:100%;
  z-index:2;
}

#myModal h2 {
  margin:0;   
}
#myModal td {
  height:30px;  

}

#myModal button {
  margin: auto;
  display: block;
  width:480px;
  height:15px;
  border:none;
  background-color:#fff;
  color: #A20131;
  font-size:12px;
  padding: 0px 10px 2px;
}

#myModal .modal_content {
  width:700px;
  height:700px;
  margin: 50px 500px auto;
  padding: 20px;
  border-radius:10px;
  background:#fff;
  overflow-y: scroll;
}
#myModal .modal_content .mContent {
  padding:15px 15px 10px;
  max-height: calc(100vh-200px);
  overflow-y: auto;
}
#myModal .modal_content .mTitle {
  padding:5px 5px;
  overflow-y : initial !important
}
#myModal .modal_layer {
  position:fixed;
  top:0;
  left:0;
  width:100%;
  height:100%;
  background:rgba(0, 0, 0, 0.5);
  z-index:-1;
  
}  

</style>
<script src="/modal/classTime.html"></script>
 	<script type="text/javascript">
	    function fnViewTime() {
	        // 동적으로 모달 창 생성
	        var modalDiv = $('<div id="myModal">' +
	            '<div class="modal_layer">' +
	            '</div>' +
	            '</div>');
	
	        // 모달 창을 현재 페이지의 body에 추가
	        $('body').append(modalDiv);
	
	        // HTML 파일을 불러와 모달 창에 추가
	        modalDiv.find('.modal_layer').load('/modal/classTime.html', function () {
	            // 부트스트랩의 modal 함수를 호출하여 모달을 띄움
	            modalDiv.modal('show');
	        });
	    }
	    

        function close_pop() {
            $('#myModal').remove();  // 모달 창을 제거
        }
    </script>

<style type="text/css">
* {
	box-sizing: border-box;
}

#head_bar {
	overflow: visible;
	height: 30px;
	line-height: 30px;
	width: 100%;
	background-color: #dadada;
}

#head_bar .one {
	float: left;
	height: 30px;
	width: 10%;
	font-size: 10px;
	text-align: center;
	line-height: 30px;
	background-color: #a20131;
	color: #fff;
	box-sizing: border-box;
	margin-right: 100px;
}

#head_bar .ttt {
	float: left;
	height: 30px;
	width: 80px;
	line-height: 30px;
	text-align: center;
	font-size: 10px;
	margin-right: 1px;
}

#head_bar .ttt_1 {
	float: left;
	background-color: white;
	text-align: center;
	line-height: 20px;
	height: 20px;
	width: 100px;
	font-size: 10px;
	border: solid 1px black;
	margin: 5px;
}

#btn_bar {
	margin: 5px;
}

#btn_bar .btn {
	float: left;
	background-color: #a20131;
	width: 120px;
	height: 30px;
	margin-right: 15px;
	border-radius: 5px;
	border-width: 2px;
	text-align: center;
	color: #fff;
	margin-bottom: 20px;
	cursor: pointer;
}

#list_head {
	width: 100%;
	text-align: center;
	margin-left: 0px;
	margin-bottom: 50px;
	white-space: nowrap;
}

#sub_list {
	float: left;
	text-align: center;
	height: 30px;
	width: 100%;
	margin-left: 5px;
	border-collapse: collapse;
	margin-bottom: 20px;
}

.tr th {
	background-color: #dadada;
}

tr {
	height: 30px;
}

#list_head .delete_btn {
	height: 20px;
	width: 35px;
	font-size: 8pt;
	background-color: grey;
	color: #fff;
	border-radius: 2px;
	border-width: 1px;
	cursor: pointer;
}

#head_bar .list_btn, #list_head .list_btn {
	height: 20px;
	width: 35px;
	font-size: 8pt;
	background-color: #a20131;
	color: #fff;
	border-radius: 2px;
	border-width: 1px;
	cursor: pointer;
}

.jpg {
	float: left;
	width: 30px;
	height: 30px;
	background-color: #a20131;
	color: #fff;
	text-align: center;
	font-size: 20px;
}

.jpg1 {
	float: left;
	width: 30px;
	height: 30px;
	background-color: #808080;
	color: #fff;
	text-align: center;
	font-size: 20px;
}

#list_jpg {
	float: left;
	width: 100%;
	margin-bottom: 20px;
}
 table {
    border-collapse: collapse;
    width: 100%;
}

.th {
    border: 1px solid #dddddd;
    text-align: left;
    padding: 8px;
} 
 .hidden-comma {
    display: none; /* 숨김 처리 */
}
#array{
	background-color: #dadada;
	border: 0px;

}
/* tr:nth-child(even) {
    background-color: #f2f2f2;
} */
</style>