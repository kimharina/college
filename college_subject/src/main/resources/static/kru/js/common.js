$(function(){
	/*** 팝업 ****/
	//팝업 중앙정렬(레이어팝업) → transform 방식으로 변경
	/*function pop_locSet(){
		var popW = $(".popLayout, .popLayout2").width();
		var popH = $(".popLayout, .popLayout2").height();

		if($(".popLayout, .popLayout2").hasClass("popWin")){
			if($(".popLayout, .popLayout2").parents('div').attr('class') == 'pop_wrap'){
				$(".popLayout, .popLayout2").css({
					"margin-left": -(popW / 2),
					"margin-top": -(popH / 2)
				});
			}
		}else{
			$(".popLayout, .popLayout2").css({
				"margin-left": -(popW / 2),
				"margin-top": -(popH / 2)
			});
		}

		if(window.innerWidth < 1041){
			$(".popLayout .limit, .popLayout2 .limit").css("height", window.innerHeight - 110);
		}else{
			$(".popLayout .limit, .popLayout2 .limit").css("height", "");
		}
	}*/

	$(".popLayout .btn_popClose, .popLayout2 .btn_popClose").click(function(){
		//$(this).parents("").fadeOut(200);
		//$(this).parent(".pop_wrap, .popLayout, .popLayout2").fadeOut(200);
		$(this).parents(".pop_wrap").fadeOut(200);
		return false;
	});

	$(window).bind('load resize', function(){
		//pop_locSet() // 팝업 위치 셋팅
	});

});
