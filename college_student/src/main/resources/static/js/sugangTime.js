// 시간을 체크하고 알맞은 함수 호출
function checkTimeAndPerformAction() {
	$.ajax({
	    type: "POST",
	    url: "/sugang/getTime",  // 위에서 설정한 엔드포인트 URL
	    dataType: "json",  // 응답 데이터 타입
	    success: function(response) {
	        // 서버에서 받은 데이터를 사용
	        console.log("서버로부터 받은 데이터:", response);
	        console.log("수강신청시작:", response.targetDateTime);
	        console.log("수강신청마감:", response.endTargetDateTime);
	
	        var target = new Date(response.targetDateTime);
	        var endTarget = new Date(response.endTargetDateTime);
		    var currentDateTime = new Date();
		                           
			 // 특정 시간 이후에 페이지를 열기
		    if (endTarget > currentDateTime && currentDateTime >= target) {

		    } else {
		        // 그 외의 시간에는 페이지가 닫혀 있음을 나타내는 문구를 표시
		    	// timePage를 보이게 설정
		        document.getElementById('timePage').style.display = 'block';
		        // 기타 페이지를 숨기게 설정
		        document.getElementById('notePage').style.display = 'none';
		        document.getElementById('codePage').style.display = 'none';
		        document.getElementById('cartPage').style.display = 'none';
			}
		  },
	    error: function(xhr, status, error) {
	        console.error("서버와의 통신 중 오류:", status, error);
	    }
	});

};

// 페이지 로딩 후 시간 체크 함수 호출
function onLoad() {
    checkTimeAndPerformAction();
}

window.onload = onLoad;

