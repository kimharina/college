<%@ page language="java" contentType="text/html; charset=UTF-8"
   pageEncoding="UTF-8"%>
<%@ include file="../sideBar_SLogin.jsp"%>
<script type="text/javascript" src="/js/sugangTime.js" ></script>
<script src="https://code.jquery.com/jquery-latest.js"></script>
<script type="text/javascript">
   $(function() {
      // 초기 페이지 설정
      showPage("notePage");

      // 탭 클릭 이벤트 처리
      $(".sugang-header > span").click(function() {
         
         var pageId = $(this).attr("data-page"); //클릭한 페이지의 이름을 pageId에 저장

         $(this).addClass("selected").siblings().removeClass("selected");

         showPage(pageId);
      });

      function showPage(pageId) {
         // 숨겨진 모든 페이지 숨김
         $(".page").addClass("hidden");

         // 선택한 페이지만 표시
         $("#" + pageId).removeClass("hidden");
         
         if(pageId=="codePage"){
            $("#Search").click();   //처음에 전체 리스트 뜨도록 하기
         }
      }
   });

</script>

<body>
   <div class="sugang-header">
      <span id="note" data-page="notePage" class="selected">유의사항</span> 
      <span id="code" data-page="codePage">과목코드로 신청</span> 
      <span id="cart" data-page="cartPage">관심과목으로 신청</span>

   </div>
   <div style="margin-left: 10px; margin-top: 70px">

      <!-- 유의사항 -->
      <div id="notePage" class="page">
         <br>
         <h1 id="h1Title">수강신청 사용안내</h1>

         <div class="info-box" id="boxKOR">
            <ol>
               <ul class="list-icon">
                  <li><a href="javascript:fnNotice()">수강신청시스템 중복로그인/매크로 제한
                        기능 도입 안내</a></li>
                  <div id="notiMacro" style="display: none;">
                     <ul style="margin-left: 18px;">
                        <li>2013학년도 2학기 수강신청부터(2013학년도 여름계절수업 시범 운영) 모든 사용자에게 공정하고
                           원활한 수강신청 서비스를 제공하고자<br> 아래와 같은 제한 기능을 도입하오니 학생 여러분께서는 수강신청
                           시 아래 내용을 필히 숙지하여 주시기 바랍니다.<br> 아래 기능 도입으로 인하여 본인의 아이디와
                           패스워드를 타인에게 빌려주면 원치 않게 로그아웃이 될 수 있으니, 본인 계정 관리에 신중을 기하여 주시기
                           바랍니다.
                        </li>
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
                              <li>수강신청저장을 일정횟수를 초과하여 시도 할 때마다 임의의 문자열 이미지를 무작위로 화면에
                                 표시하고 문자열을 올바르게 입력 했을 경우 수강신청 저장이 가능합니다.</li>
                           </ul>
                        </li>
                     </ul>
                  </div>
               </ul>
            </ol>

            <ul class="list-icon">
               <li>Microsoft의 Internet Explorer 지원 종료에 따라 Chrome, Firefox,
                  Edge 브라우저를 이용하시기 바랍니다.</li>
               <li class="highlight">장애학생 수강신청 - 8. 1(화) 10:00 - 8. 2(수)
                  09:00</li>
               <li class="highlight">수강희망과목 등록기간 - 8. 2(수) 13:00 - 8. 4(금)
                  12:00</li>
               <li class="highlight">신입생 수강신청 기간 - 8. 22(화) 10:00 - 8. 23(수)
                  12:00</li>
               <li class="highlight">수강신청 기간 - 8. 16(수) 10:00부터 시작, 4학년을 시작으로
                  학년별로 수강신청을 진행함.</li>
               <li class="highlight">수강신청 정정 기간 - 9. 6(수) 18:30부터 시작, 4학년을
                  시작으로 학년별로 한 시간 간격으로 시작시간을 달리함.</li>
               <li class="highlight">수강 및 성적평가 공정성 제고 관련 교육부 권고에 따라, 부모 중 1인
                  이상이 강의를 담당하는 과목의 경우 자녀의 수강이 제한될 수 있습니다.</li>
               <li>학사관련 주요사항 안내는 교육정보 홈페이지를 참조하세요. <a
                  href="http://registrar.korea.ac.kr" target="_blank">교육정보 바로가기</a></li>
               <li>단과대학별 수강신청 유의사항은 교육정보 홈페이지를 참조하세요. <a
                  href="http://registrar.korea.ac.kr/eduinfo/info/registration_caution.do"
                  target="_blank">교육정보 바로가기</a></li>
               <li><b>암호</b>
                  <ul class="list-dot">
                     <li>포털(KUPID)사용자 : 포털비밀번호</li>
                     <li>포털(KUPID)미사용자 : '포털미사용자 비밀번호변경'에서 설정한 비밀번호(설정전: 주민번호뒷자리)</li>
                     <li>(포털사용중인 신입생도 개강전에는 포털미사용자에 해당하는 비밀번호 사용)</li>
                  </ul></li>
               <li><b>암호 분실시</b>
                  <ul class="list-dot">
                     <li>포털 사용자 : <a href="http://portal.korea.ac.kr"
                        target="_blank">포털(http://portal.korea.ac.kr)</a> 로그인 화면의 <strong>'비밀번호찾기'</strong>에서
                        비밀번호 재발급
                     </li>
                     <li>포털(KUPID)미사용자 : <span class="txt-blue">수강신청(https://sugang.korea.ac.kr)</span>
                        <strong>'포털미사용자 비밀번호변경'</strong> 메뉴에서 비밀번호 재발급
                     </li>
                     <li class="highlight">포털에서 비밀번호를 변경 또는 재발급 받은 경우는 10분후에 로그인
                        하기 바랍니다.</li>
                  </ul></li>
               <li><a href="javascript:fnExchange()">국내 교류 학생의 학번 확인</a></li>
               <li>Internet Explorer 10 이상의 버전, 화면 해상도 1920*1080에 최적화 되어
                  있습니다.</li>
            </ul>
         </div>
      </div>
      <!-- 과목코드로 신청 -->
      <div id="codePage" class="page hidden">
      <table>            
         <tr>
            <td style="text-align: center;">
               <select name="select" id="select" style=" width: 75px;height:23px;margin-right: 8px;">
                  <option value="subject_Name" name="subject_Name" >과목명</option>
                  <option value="subject_No" name="subject_No">과목코드</option>
               </select>
               <input type="text" style="width: 200px;margin-right: 5px;" name="subjectCode" id="subjectCode" value="" placeholder="과목명/과목코드" /> 
               <input type="button" id="Search" value="검색">
               <button type="button" id="btnReset" onclick="javascript:fnReset()">초기화</button>
            </td>
         </tr>
      </table>
      <br><br>
      <div id=list_head style="max-height: 500px; overflow-y: auto;">
         <table border="1" id="sub_list">
            <tr class="tr">
               <th class="th" style="width: 5%;">과목코드</th>
               <th class="th" style="width: 5%;">이수구분</th>
               <th class="th" style="width: 20%;">교과목명</th>
               <th class="th" style="width: 5%;">학년</th>
               <th class="th" style="width: 3%;">학점</th>
               <th class="th" style="width: 5%;">요일</th>
               <th class="th" style="width: 10%;">시간</th>
               <th class="th" style="width: 10%;">개설학과</th>
               <th class="th" style="width: 5%;">교수</th>
               <th class="th" style="width: 5%;">저장</th>
            </tr>
         </table>
         <div id="result"></div>
      </div>
   </div>

<!-- 관심과목으로 신청 -->
<div id="cartPage" class="page hidden">

      <br><br>
      <div id=list_jpg>
   
         <div class=jpg>></div>
   
         <div>
            <b>수강 신청</b>
            <button id="" class="cart_btn">신청</button>
         </div>
   
      </div>
      <div id=list_head style="max-height: 500px; overflow-y: auto;">
         <table border="1">
            <tr class="tr">
               <th class="th" style="width: 5%;">과목코드</th>
               <th class="th" style="width: 5%;">이수구분</th>
               <th class="th" style="width: 20%;">교과목명</th>
               <th class="th" style="width: 5%;">학년</th>
               <th class="th" style="width: 3%;">학점</th>
               <th class="th" style="width: 5%;">요일</th>
               <th class="th" style="width: 10%;">시간</th>
               <th class="th" style="width: 10%;">개설학과</th>
               <th class="th" style="width: 5%;">교수</th>
               <th class="th" style="width: 5%;">취소</th>
            </tr>
         </table>
         <div id="cart_result"></div>
      </div>

   </div>
   


   <!-- 수강신청기간 아닐때 -->
   <div id="timePage" class="page hidden">
      <ul class="list-icon" style="margin-bottom:10px">
         <li><b>수강신청 안내</b></li>
      </ul>
      
      <div class="info-box" style="padding:5px 25px">         
         <div id="legendKOR" style="display:block;" class="highlight">
            <ul class="list-dot">
               <li>수강신청 기간이 아닙니다.</li>
            </ul>
         </div>
      </div>
   </div>
   </div>      

</body>
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
}


.tr th {
   background-color: #dadada;
}

tr {
   height: 30px;
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
.list_btn{
   height: 25px;
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

#list_jpg {
   float: left;
   width: 100%;
   margin-bottom: 20px;
}

.sugang-header {
   width: 100%;
   margin-top: 10px;
}
.sugang-header span {
   float: left;
   width: 20%;
   height: 40px;
   background: #b3b3b3;
   font-size: 14px;
   color: #fff;
   line-height: 38px;
   text-align: center;
   margin-right: 25px;
   cursor: pointer
}

.sugang-header span.selected {
   background: #a20131;
   cursor: default
}

/* tr:nth-child(even) {
    background-color: #f2f2f2;
} */
</style>

</html>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>

<script>
//과목코드로 신청에서 검색기능 
$(document).ready(function() {
   $("#Search").on("click", function () {
         var searchData = {
             select: $("#select").val(),
             search: $("#subjectCode").val()
         };
         $.ajax({
                 type: "POST",
                 url: "/sugang/search",
                 data: JSON.stringify(searchData),
                 headers: {
                     'Content-Type': 'application/json',
                     'Authorization': localStorage.getItem('Authorization'),
                 },
                 success: function (data) {
                     console.log(data);
                  // data가 배열이 아니면 배열로 변환
                     var dataArray = Array.isArray(data) ? data : [data];

                     // 결과를 담을 변수
                     var tableHTML = '<table border="1" id="sub_list">';
                         // 여기에 필요한 헤더 등을 추가

                         // 결과 데이터를 테이블에 추가
                         dataArray.forEach(function (subjects) {
                             tableHTML += '<tr class="tr">';
                             tableHTML += '<td class="th" style="width: 5%;">' + subjects.subject_No + '</td>';
                             tableHTML += '<td class="th" style="width: 5%;">' + subjects.subject_Type + '</td>';
                             tableHTML += '<td class="th" style="width: 20%;">' + subjects.subject_Name + '</td>';
                             tableHTML += '<td class="th" style="width: 5%;">' + subjects.grade + '</td>';
                             tableHTML += '<td class="th" style="width: 3%;">' + subjects.subject_Point + '</td>';
                             tableHTML += '<td class="th" style="width: 5%;">' + subjects.day + '</td>';
                             tableHTML += '<td class="th" style="width: 10%;">' + subjects.start_Time_Output + ' ~ ' + subjects.end_Time_Output + '</td>';
                             tableHTML += '<td class="th" style="width: 10%;">' + subjects.department_Name + '</td>';
                        tableHTML += '<td class="th" style="width: 5%;">' + subjects.professor_Name + '</td>';
                             tableHTML += '<td class="th" style="width: 5%;"><input type="button" value="신청" class="list_btn" data-subject-no="' + subjects.subject_No + '" /></td>';
                             // 나머지 필드도 동일하게 추가
                             tableHTML += '</tr>';
                         });
                         tableHTML += '</table>';
                     // 결과를 HTML에 반영
                     $('#result').html(tableHTML);

                 },
                   error: function (xhr, status, error) {
                     // 에러 처리
                     console.error("데이터 전송 중 오류가 발생했습니다. Status: " + status + ", Error: " + error);
                 }
         });
   });
   
   //과목코드 신청
   $(document).ready(function() {            

      $('#result').on('click', '.list_btn', function() {
           var tr = $(this).closest('tr');    // 저장 버튼을 누른 행을 찾습니다.
           var subjectNo = $(this).data('subject-no');
           
            console.log("과목코드 : "+ subjectNo);
               $.ajax({   
                   type: "POST",
                   url: "/sugang/sugang",
                   contentType: "application/json",
                   data: JSON.stringify({ "subjectNo": subjectNo }),
                   headers: {
                     'Content-Type': 'application/json',
                     'Authorization': localStorage.getItem('Authorization'),
                 },
                   success: function(data) {
                       // 서버에서 응답을 받은 후의 작업 
                       console.log("데이터가 성공적으로 서버에 전송되었습니다.");
                       if(data == "신청 완료"){
                          alert("수업이 신청되었습니다.");

                       } else if (data == "같은 시간에 이미 수업이 있습니다."){
                          alert("신청 실패 : 같은 시간에 이미 수업이 있습니다.");

                       } else if (data =="인원이 초과되었습니다."){
                          alert("인원이 초과되었습니다.");
                          
                      } else if (data =="신청 실패"){
                          alert("신청 실패");

                      } else {
                          localStorage.removeItem("Authorization");
                          alert("다시 로그인해주세요.");
                          window.location.href = '/student/login';
                      }
                  },
                  error: function (xhr, status, error) {
                      if (xhr.status === 401) {
                          // Unauthorized 상태
                          localStorage.removeItem("Authorization");
                          window.location.href = '/student/login';
                      } else {
                          // 다른 오류 처리
                          console.error("데이터 전송 중 오류가 발생했습니다. 상태: " + status + ", 오류: " + error);
                      }
                  }
              });
          });
      });
   

   
});
function fnReset() { //초기화 기능
   $("#subjectCode").val("");      
   $("#select").val("subject_Name");      
   $("#Search").click();
}


//관심과목으로 신청 - (1) 나타내기
$.ajax({
    url: "/sugang/request",  
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
                tableHTML += '<td class="th" style="width: 5%;">' + carts.subject_No + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 5%;">' + carts.subject_Type + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 20%;">' + carts.subject_Name + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 5%;">' + carts.grade + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 3%;">' + carts.subject_Point + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 5%;">' + carts.day + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 10%;">' + carts.start_Time_Output + ' ~ ' + carts.end_Time_Output + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
                tableHTML += '<td class="th" style="width: 10%;">' + carts.department_Name + '</td>';
                tableHTML += '<td class="hidden-comma">,</td>';
            tableHTML += '<td class="th" style="width: 5%;">' + carts.professor_Name + '</td>';
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

//관심과목으로 신청 - (2) 취소하기
$(document).on("click", ".delete_btn", function() {
    var tr = $(this).closest('tr');
    var subjectNoToDelete = tr.find('.subject_no_column').text().trim(); // subject_no를 찾는 로직 추가

    // 행 삭제
    tr.remove();

    // 서버에서 데이터 삭제
    $.ajax({
        url: "/sugang/delete-endpoint",
        type: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': localStorage.getItem('Authorization'),
        },
        data: JSON.stringify({ subject_No: parseInt(tr.find('.th').eq(0).text().trim()) }), // 첫 번째 td에서 subject_No 값을 얻어와 정수로 변환
        success: function(response) {
            console.log("데이터가 성공적으로 삭제되었습니다.");
            console.log(response);
            alert("장바구니 취소 완료!");
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

//관심과목으로 신청 - (3) 수강신청 버튼 누르기
 $(document).on("click", ".cart_btn", function () {
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
        url: "/sugang/request_final",
        contentType: "application/json",
        data: JSON.stringify({ subject_No: subjectNos }),  // 전체 행 데이터를 배열로 묶어서 전송
        headers: {
            'Content-Type': 'application/json',
            'Authorization': localStorage.getItem('Authorization'),
        },
        dataType: 'text', 
        success: function (response) {
            console.log("수강신청 완료!");
            console.log(response);
            if(response.includes("인원이 마감되었습니다.")) {
                alert(response);
            } else if(response.includes("같은 시간대에 이미 과목이 있습니다.")) {
           	 alert(response); // 서버로부터 받은 응답을 알림창으로 표시
            } else {
	            alert("수강신청 완료!");
	            $('#cart_result').empty();
            }
        },
        error: function (error) {
            console.error("수강신청 중 오류가 발생했습니다.", error);
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