<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="../sideBar.jsp"%>
<div id="contents" class="contents">
<script type="text/javascript" language="javascript">
    // 초기 페이지로 설정
    $(document).ready(function () {
        f_calls(1);
    });
    function fnHeight() {
        $('#mainF').prop("height", $(window).height() - 250);
    }
    function f_calls(str) {
        let strUrl = "/resources/link/";
        let page = "";
        switch (str) {
            case 1:
                page = "A001.html";
                break;
            case 2:
                page = "A002.html";
                break;
            case 3:
                page = "A003.html";
                break;
            case 6:
                page = "A006.html";
                break;
            case 7:
                page = "A009.pdf";
                break;
            case 13:
                page = "E003.html";
                break;
            case 12:
                page = "A002.html";
                break;
            case 14:
                page = "E004.html";
                break;
            case 15:
                page = "E005.html";
                break;
            case 17:
                page = "A009.pdf";
                break;
            case 20:
                page = "A020.html";
                break;
            default:
                break;
        }
        // 페이지 변경
        document.getElementById('mainF').src = strUrl + page + "?fake=" + Date.now();
        fnHeight();
    }
</script>
	<title>SugangNotice</title>
	<style type="text/css" media="screen">
body, form, h1, h2, h3, h4, h5, h6, p, ul, ol, li, dl, dt, dd {
	padding: 0;
	margin: 0;
}

#wrap {
	width: 100%;
	margin: 0;
	padding: 0;
}

body {
	font-family: arial, verdana, sans-serif;
	font-size: 12px;
	color: #404040;
}

div {
	margin: 0;
}

#thirdMenu {
	border: 5px solid #eee6d4;
	width: 100%;
	padding: 10px 10px 10px 10px;
	overflow: hidden;
}

#thirdMenu #menu {
	margin: 0;
	padding: 0 0 10px 0
}

#thirdMenu li {
	float: left;
	margin: 0;
	padding: 0;
	display: inline;
	list-style-type: none;
}

#thirdMenu a {
	display: block;
	/* background: url(images/ic_triorg.gif) no-repeat 0 50%; */
	text-decoration: none;
	padding: 3px 10px 0px 10px;
	color: #404040;
}

#thirdMenu a.active, #thirdMenu a:hover {
	color: #a82721;
}

.dotline {
	/* background: url(images/dotline_2x1y.gif) repeat-x 0 50%; */
	float: left;
	margin: 5px 0px 5px 0px;
	width: 100%;
	height: 1px;
}
</style>

	<div id="wrap">

		<div id="thirdMenu">
			<ul id="menu">

				<li><a href="#" onclick="f_calls(1)">수강신청안내</a></li>
				<li><a href="#" onclick="f_calls(20)">대학별 수강신청 유의사항</a></li>
				<li><a href="#" onclick="f_calls(2)">수업시간표</a></li>
				<li><a href="#" onclick="f_calls(3)">강의계획안 학생의견 수렴</a></li>
				<li><a href="#" onclick="f_calls(6)">수강희망과목 등록제도 안내</a></li>
				<li><a href="#" onclick="f_calls(7)">저작권법 유의사항 안내</a></li>


			</ul>
			<!-- <div class="dotline"></div>
	<ul id="menu">
		<li><a href="#" onClick="f_calls(34)">교직관련 유의사항</a></li>
		<li><a href="#" onClick="f_calls(37)">평생교육사</a></li>
	</ul> -->
		</div>

	</div>

	<div style="margin-left: 10px; margin-top: 10px">
		<iframe id="mainF" name="mainF" src=f_calls(this) style="
			display:block; width:100%; height: 80vh" marginwidth="0"
			marginheight="0" scrolling="auto" frameborder="0"
			onload="fnHeight()" height="718">
		</iframe>
	</div>
</div>
</body>
</html>