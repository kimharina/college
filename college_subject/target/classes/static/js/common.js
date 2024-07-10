
$(document).ready(function(){
	
	// 메뉴 타이틀 체크 ( 메뉴가 없는 경우 왼쪽 메뉴 갱신 )
//	if($("#sideContent h1").children().length == 0){
	if($("#sideContent h1").length == 0){
		$('#sideContent').append("<h1>"+$('#pageTitle').text()+"</h1>");
		$('#location').html("");
	}
})

/* function valueEmpty */
jQuery.fn.valueEmpty = function() {
    if (jQuery.trim(jQuery(this).val()).length < 1 ) {
        return true;
    } else {
        return false;
    }
};

/* function number and comma */
function numComma(data){
	if (jQuery.trim(data).length > 3 ) {
    	var returnValue = "";
        var commaValue = ""+data;
        for(idx=commaValue.length-1,chk=0;idx>=0;idx--,chk++){
        	if(chk == 3){
        		chk=0;
        		returnValue = commaValue.substr(idx,1) + "," + returnValue;
        	} else {
        		returnValue = commaValue.substr(idx,1) + returnValue;
        	}
        }
        return returnValue;
    } else {
        return data;
    }
}

$(function () {
	/* function onlyNumber */
	$(".onylNum").change(function(){
		$(this).val($(this).val().replace(/[^0-9]/g,""));
	});
})

//파일 다운로드
function mfn_fileDownload(fileKey){
	if(fileKey != "" || fileKey == null){
		location.href="/common/fileDownload.do?fileKey="+fileKey;	
	}
};

// 인쇄
$(document).on("click", ".btnPrint", function(){
	var initBody = document.body.innerHTML;

	window.onbeforeprint = function () {
		document.body.innerHTML = document.getElementById("subContent").innerHTML;
	}

	window.onafterprint = function () {
		document.body.innerHTML = initBody;
	}

	window.print();
});

$(function(){
	//도움말기능 시작
	$(".adminHpcmIcon").click(function(){
		
		var obj = $(this);
		chk = obj.attr('chk');
		if (chk == null) {
			chk = 1;
		}
		
		if (chk == 1) {
			$.ajax({
				type : "get",
				url : "/apple/hc/hpcm/selectHpcm.do",
				data : {"hpcmSn" : $(this).attr("data-hp")},
				dataType : "json",
				success:function(data){
					obj.popover({
						title : data.hpcmSj,
						container : "body",
						toggle : "popover",
						placement : "right",
						trigger: 'focus',
						html : "true",
						content : data.hpcmDc
					}).popover('show');
					obj.attr('chk','0');
				},
				error : function(error) {
					alert("오류가 발생하였습니다.\n관리자에게 문의하세요.");
				}	
			});
		}else{
			obj.attr('chk','1');
		}
	})
	
	//도움말기능 시작(공통)
	$(".hpcmIcon").click(function(){
		
		var obj = $(this);
		chk = obj.attr('chk');
		if (chk == null) {
			chk = 1;
		}
		
		if (chk == 1) {
			$.ajax({
				type : "get",
				url : "/common/hc/hpcm/selectHpcm.do",
				data : {"hpcmSn" : $(this).attr("data-hp")},
				dataType : "json",
				success:function(data){
					obj.popover({
						title : data.hpcmSj,
						container : "body",
						toggle : "popover",
						placement : "right",
						trigger: 'focus',
						html : "true",
						content : data.hpcmDc
					}).popover('show');
					obj.attr('chk','0');
				},
				error : function(error) {
					alert("오류가 발생하였습니다.\n관리자에게 문의하세요.");
				}	
			});
		}else{
			obj.attr('chk','1');
		}
	})
	
	
})
//도움말기능 끝

// 메뉴 접근 권한 체크
function menuAccessCheck(mi, sysId){
	var url = "/" + sysId + "/mn/menu/menuAccess.do"
	
	$.ajax({
		type : "post",
		url : url,
		data : { 
			menuId : mi
		},
		dataType : "json",
		success : function(data) {
			var accessVal = JSON.parse(data.accessVal);
			
			if (accessVal == "Y") {
				var accessUrl = JSON.parse(data.menuUrl);
				location.href = accessUrl;
			} else {
				alert("접근 권한이 없습니다.");
				return false;
			}
		},
		error : function(data) {
			alert("오류가 발생하였습니다.\n관리자에게 문의하세요.");
		}		
	});	
}

//팝업 쿠키 저장
function setCookie(cookieName, value){
    var exdays = 1;
    var exdate = new Date();
    var day = exdate.getDate() * 1;
    exdate.setDate(day + exdays);
//    var cookieValue = escape(value) + ((exdays==null) ? "" : "; expires=" + exdate.toGMTString());
    var cookieValue = escape(value) + ((exdays==null) ? "" : "; expires=" + exdate.toUTCString()); 
    document.cookie = cookieName + "=" + cookieValue;
}

// 쿠키조회
function getCookie(cookieName) {
    cookieName = cookieName + '=';
    var cookieData = document.cookie;
    var start = cookieData.indexOf(cookieName);
    var cookieValue = '';
    if(start != -1){
        start += cookieName.length;
        var end = cookieData.indexOf(';', start);
        if(end == -1)end = cookieData.length;
        cookieValue = cookieData.substring(start, end);
    }
    return unescape(cookieValue);
}

// 팝업 닫기(쿠키설정)
$(document).on('click', '.popupCookieSet', function() {
	var popValue = $(this).attr("data-seq");
	var cookieNM = "popCookie"+popValue;
	
//	setCookie(cookieNM, "hide", "1");
	setCookie(cookieNM, "hide");
	$("#popupNormal"+popValue).parent().remove();
});

