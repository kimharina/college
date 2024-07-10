$(function(){
	/*** main 공통 ***/
	/*$(".list_control").each(function(){
		var slick_num = $(this).prev('div').find('button').first().text();
		if($(this).prev('div').has('button')){
			$(this).show();
		}else{
			$(this).hide();
		}
	});*/

	$(".list_control>button").click(function(){
		if($(this).attr('class') == 'btn_pause'){
			$(this).attr("class", "btn_play").text('재생');
			$(this).parent().siblings('.slick-slider').slick('slickPause');
			return false;
		}
		if($(this).attr('class') == 'btn_play'){
			$(this).filter('.btn_play').attr("class", "btn_pause").text('일시정지');
			$(this).parent().siblings('.slick-slider').slick('slickPlay');
			return false;
		}
	});


	/*** main 개별 ***/
	var headTopBnr_num = $('#headTop_bnr .list .bnr').length;
	if(headTopBnr_num > 1){
		$('#headTop_bnr .list').removeClass('bnr01').addClass('bnr02')
	}else{
		$('#headTop_bnr .list').removeClass('bnr02').addClass('bnr01')
	}
	$("#headTop_bnr .btn>.btn_close").click(function(){
		$("#header").removeAttr('style');
		$("body").removeClass('typeHeadBnr');

		// pop_zone resize
		if( window.innerWidth > 1041){
			var conts_load = $("body").offset().top;
			var conts_loc = $(window).scrollTop();

			if($("body").hasClass('typeHeadBnr') && conts_loc == 0){
				$(".popZone").css({
					"top": "266px",
					"height": window.innerHeight - 166
				})
			}else if($("body").hasClass('typeHeadBnr') && conts_loc > 0 && conts_loc < 150){
				$(".popZone").css({
					"top": $("#headTop_bnr").height() - $("#header").height() + conts_loc + 31,
					"height": window.innerHeight - $("#headTop_bnr").height() - $("#header").height() + conts_loc
				})
			}else{
				$(".popZone").css({
					"top": "116px",
					"height": window.innerHeight - 116
				})
			}
		}
	});

	$('#headTop_bnr .list').slick({
		accessibility: true,/*190620 추가*/
		infinite: true,
		arrows: true,
		dots: false,
		slidesToShow: 2,
		slidesToScroll: 1,
		swipeToSlide: true,
		focusOnSelect: true,
		autoplay: false,
		autoplaySpeed: 5000,
		responsive: [
			{
				breakpoint: 768,
				settings: {
					slidesToShow: 1,
					slidesToScroll: 1
				}
			}
		]
    });

	if($(".mTopBnr [name=AUTO_ROLL_YN]").val()=="Y"){
		$('.mTopBnr .list').slick({
			accessibility: true,
			infinite: true,
			arrows: true,
			dots: false,
			slidesToShow: 1,
			slidesToScroll: 1,
			swipeToSlide: true,
			focusOnSelect: true,
			autoplay: true,
			autoplaySpeed: parseInt($(".mTopBnr [name=ROLL_TIME]").val()==""?"3":$(".mTopBnr [name=ROLL_TIME]").val())*1000
		});
		$('.mTopBnr').css('display','block');
	}else{
		$('.mTopBnr .list').slick({
			accessibility: true,
			infinite: true,
			arrows: true,
			dots: false,
			slidesToShow: 1,
			slidesToScroll: 1,
			swipeToSlide: true,
			focusOnSelect: true,
			autoplay: false
		});
		$('.mTopBnr').css('display','block');
	}

	function mLinkBnr_motion(){
		/*var bnrNum = $(".mLinkBnr .unit").length;
		for(i=0; i < bnrNum; i++){
			if(i == 0){
				$(".mLinkBnr .unit:nth-of-type(" + (i+1) + ")>div").animate({
					"opacity": "1"
				}, 300);
			}else{
				$(".mLinkBnr .unit:nth-of-type(" + (i+1) + ")>div").delay(i * 100).animate({
					"opacity": "1"
				}, 300);
			}
		}*/
		$(".mLinkBnr .unit:nth-of-type(1)>div").delay(10).animate({
			"opacity": "1"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(2)>div").delay(200).animate({
			"opacity": "1"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(3)>div").delay(300).animate({
			"opacity": "1"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(4)>div").delay(400).animate({
			"opacity": "1"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(5)>div").delay(500).animate({
			"opacity": "1"
		}, 400);

		$(".mLinkBnr .unit:nth-of-type(1)").delay(110).animate({
			"margin-top": "0"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(2)").delay(300).animate({
			"margin-top": "0"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(3)").delay(400).animate({
			"margin-top": "0"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(4)").delay(500).animate({
			"margin-top": "0"
		}, 400);
		$(".mLinkBnr .unit:nth-of-type(5)").delay(600).animate({
			"margin-top": "0"
		}, 400);
	}
	mLinkBnr_motion();

	$('.mLinkBnr .list').slick({
		infinite: false,
		arrows: false,
		dots: true,
		slidesToShow: 3,
		slidesToScroll: 1,
		//swipeToSlide: true, /*190731수정*/
		focusOnSelect: true,
		variableWidth: true,
		responsive: [
			{
				breakpoint: 860,
				settings: {
					slidesToShow: 2,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 768,
				settings: {
					slidesToShow: 3,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 460,
				settings: {
					slidesToShow: 2,
					slidesToScroll: 1
				}
			}
		]
	});
	$('.mLinkBnr').css('display','block');

	function mTopContFix(){
		if(window.innerWidth > 1080){
			$(".mLinkBnr .list").css("width", ((window.innerWidth - 1080)/2) + 690);
		}else if(window.innerWidth > 1041 && window.innerWidth <= 1080){
			$(".mLinkBnr .list").css("width", window.innerWidth - 390);
		}else if(window.innerWidth > 768 && window.innerWidth < 1041){
			$(".mTopBnr .list").css("width", "");
			$(".mLinkBnr .list").css("width", window.innerWidth - 330);
			$(".mLinkBnr .slick-dots").css("width", window.innerWidth - 370);
		}else if(window.innerWidth <= 768){
			$(".mTopBnr .list").css("width", window.innerWidth);
			$(".mLinkBnr .list").css("width", "");
			$(".mLinkBnr .slick-dots").css("width", window.innerWidth - 50);
		}else{
			$(".mTopBnr .list").css("width", "");
			$(".mLinkBnr .list").css("width", "");
			$(".mLinkBnr .slick-dots").css("width", "");
		}
	}

	$(".mBbs .bbsTab li>button").click(function(){
		var bbsLoc = $(this).parent().index();

		$(".mBbs .bbsTab li, .mBbs .bbsList .bbs").removeClass('on');

		$(this).parent().addClass('on');
		$(".mBbs .bbsList .bbs:nth-of-type(" + (bbsLoc+1) + ")").addClass('on');
	});

	$('.mSchedule .scheduleList').slick({
		infinite: false,
		arrows: true,
		dots: false,
		slidesToShow: 4,
		slidesToScroll: 4,
		responsive: [
			{
				breakpoint: 1041,
				settings: {
					slidesToShow: 3,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 870,
				settings: {
					slidesToShow: 2,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 768,
				settings: {
					slidesToShow: 2,
					slidesToScroll: 2
				}
			},
			{
				breakpoint: 460,
				settings: {
					slidesToShow: 1,
					slidesToScroll: 1
				}
			}
		]
	});

	/*190731수정 시작*/
	function mSchedule_focus(){
		if($(".mSchedule .scheduleList .unit").hasClass('slick-active')){
			$(this).children('a').attr('tabindex','0');
		}else{
			$(this).children('a').attr('tabindex','-1');
		}
	}
	mSchedule_focus();

	$('.mSchedule .scheduleList>button').click(function(){
		mSchedule_focus();
	});
	/*190731수정 끝*/

	$(window).bind('load resize', function(){
		$('.mSchedule .scheduleList .slick-prev').text("이전일정");
		$('.mSchedule .scheduleList .slick-next').text("다음일정");
	});

	var mMoreList_loc = $(".mSchedule .mMore_list").height();
	$(".mSchedule .mMore_list").css("bottom", -(mMoreList_loc))

	$(".mSchedule .mMore>.btn_more").click(function(){
		if($(".mSchedule .mMore").hasClass('on')){
			$(".mSchedule .mMore").removeClass('on');
			$(".mSchedule .mMore_list").animate({
				"bottom": -(mMoreList_loc)
			}, 200)
		}else{
			$(".mSchedule .mMore").addClass('on');
			$(".mSchedule .mMore_list").animate({
				"bottom": "39px"
			}, 200)
		}
	});

	///mUnivInfo
	if($(".mUnivInfo [name=AUTO_ROLL_YN]").val()=="Y"){
		$('.mUnivInfo .list').slick({
			infinite: true,
			arrows: false,
			dots: true,
			slidesToShow: 1,
			slidesToScroll: 1,
			adaptiveHeight: true,
			autoplay: true,
			autoplaySpeed: parseInt($(".mUnivInfo [name=ROLL_TIME]").val()==""?"3":$(".mUnivInfo [name=ROLL_TIME]").val())*1000
		});
	}else{
		$('.mUnivInfo .list').slick({
			infinite: false,
			arrows: false,
			dots: true,
			slidesToShow: 1,
			slidesToScroll: 1,
			adaptiveHeight: true,
			autoplay: false
		});
	}

	$(".mUnivInfo .unit .txt").each(function(){
		if(window.innerWidth >= 1041){
			var length = 85;
		}else if(window.innerWidth > 768 && window.innerWidth < 1041){
			var length = 65;
		}else if(window.innerWidth > 560 && window.innerWidth <= 768){
			var length = 105;
		}else if(window.innerWidth > 360 && window.innerWidth <= 560){
			var length = 75;
		}else{
			var length = 45;
		}
		if($(this).text().length >= length){
 		   $(this).text( $(this).text().substr(0,length) + '...' );
 	   }
	});

	$('.mDeptInfo .list').slick({
		infinite: false,
		arrows: true,
		dots: true,
		slidesToShow: 2,
		slidesToScroll: 2,
		responsive: [
			{
				breakpoint: 1041,
				settings: {
					slidesToShow: 1,
					slidesToScroll: 1
				}
			},
			{
				breakpoint: 768,
				settings: {
					slidesToShow: 2,
					slidesToScroll: 2
				}
			}
		]
	});

	var mDeptTotal;
	var mDeptCurrent;
	function numPaging(){
		mDeptTotal = $('.mDeptInfo .slick-dots>li').length
		//mDeptCurrent =  $('.mDeptInfo .list').slick('slickCurrentSlide');
		mDeptCurrent =  $('.mDeptInfo .slick-dots li.slick-active').index();
		$(".mDeptInfo .numPaging").html("<b>" + (mDeptCurrent+1) + "</b>/" + mDeptTotal + "");
	}
	numPaging();
	/*$(".mDeptInfo .slick-arrow").click(function(){
		numPaging();
	});*/

	$('.mDeptInfo .list').on('click swipe', function(event, slick, direction){
		numPaging();
	});

	var changeNum1;
	$(window).resize(function(){
		if(window.innerWidth <= 768 || window.innerWidth >= 1041){
			if(changeNum1 == 1){
				numPaging();

				changeNum1 = 0;
			}else{
				changeNum1 = 1
			}
		}else{
			if(changeNum1 == 0){
				numPaging();
				changeNum1 = 1;
			}else{
				changeNum1 = 0
			}
		}
	});

	function mDept_size(){
		if(window.innerWidth <= 768){
			$(".mDeptInfo .list .unit>a>.photo>img").css({
				"height": $(".mDeptInfo .list .unit>a>.photo").width() * 0.49
			});
		}else{
			$(".mDeptInfo .list .unit>a>.photo>img").css({
				"height": ""
			});
		}
	}

	$(window).on('load resize', function(){
		mTopContFix();
		mDept_size();

		if(window.innerWidth >= 1041){
			$(".mLinkBnr .unit").addClass('over');
		}else{
			$(".mLinkBnr .unit").removeClass('over');
		}

		/*$(".mBbs .bbsList .bbs .tit").each(function(){
			if(window.innerWidth >= 1080){
				var length = 22;
			}else if(window.innerWidth >= 1041 && window.innerWidth < 1080){
				var length = 19;
			}else if(window.innerWidth > 900 && window.innerWidth < 1041){
				var length = 30;
			}else if(window.innerWidth > 768 && window.innerWidth <= 900){
				var length = 20;
			}else{
				var length = 60;
			}
			if($(this).text().length >= length){
			   $(this).text( $(this).text().substr(0,length) + '...' );
		   }
		});*/

		$(".mBbs .bbsList .bbs .txt").each(function(){
			if(window.innerWidth >= 1041){
				var length = 30;
			}else if(window.innerWidth > 900 && window.innerWidth < 1041){
				var length = 40;
			}else if(window.innerWidth > 768 && window.innerWidth <= 900){
				var length = 30;
			}else{
				var length = 40;
			}
			if($(this).text().length >= length){
			   $(this).text( $(this).text().substr(0,length) + '...' );
		   }
		});
	});

	//*** keyboard nav ***//*190620 추가*/
	var bbsNumLoc = $(".mBbs .bbsTab>ul>li").length;
	var bbsLoc;
	$(".mBbs .bbsTab>ul>li>button").keydown(function(event){
		bbsLoc = $(this).parent('li').index();

		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				if($(this).parent('li').is(':first-child')){
					/*190718수정 시작*/
					if($(".mLinkBnr .list").hasClass('slick-dotted')){
						$(".mLinkBnr .slick-dots li:last-child").find('button').last().focus();
					}else{
						$(".mLinkBnr .unit:last-child").find('a').first().focus();
					}
					/*190718수정 시작*/
				}else{
					$(".mBbs .bbsTab>ul>li").removeClass('on');
					$(".mBbs .bbsTab>ul>li").eq(bbsLoc-1).addClass('on');

					$(".mBbs .bbsList .bbs").removeClass('on');
					$(".mBbs .bbsList .bbs:nth-of-type(" + (bbsLoc) + ")").addClass('on');
					$(".mBbs .bbsList .bbs.on").find('.btn_more').first().focus();
				}
				return false;
			}else{
				/*190718수정 시작*/
				$(".mBbs .bbsList .bbs.on li:first-child").find('a').first().focus();
				$(".mBbs .bbsList .bbs.on .no_article").focus();
				/*190718수정 끝*/
				return false;
			}
		}
	});
	$(".mBbs .bbsList .bbs>ul>li:first-child>a").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$(".mBbs .bbsTab>ul>li.on").find('button').first().focus();
				return false;
			}else{}
		}
	});
	$(".mBbs .bbsList .bbs .btn_more").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				if($(this).parent('li').is(':first-child')){
					$("#gnb_parent>li").eq(gnbLoc).find('a').first().focus();
					return false;
				}
			}else{
				if(bbsLoc+1 != bbsNumLoc){
					$(".mBbs .bbsTab>ul>li").removeClass('on');
					$(".mBbs .bbsTab>ul>li").eq(bbsLoc+1).addClass('on');
					$(".mBbs .bbsTab>ul>li").eq(bbsLoc+1).find('button').first().focus();

					$(".mBbs .bbsList .bbs").removeClass('on');
					$(".mBbs .bbsList .bbs:nth-of-type(" + (bbsLoc+2) + ")").addClass('on');
					return false;
				}
			}
		}
	});
	/*190718수정 시작*/
	$(".mBbs .bbsList .bbs .no_article").keydown(function(event){
		var v_keyCode = event.keyCode || event.which;
		if(v_keyCode == 9){
			if(event.shiftKey){
				$(".mBbs .bbsTab>ul>li.on").find('button').first().focus();
				return false;
			}else{}
		}
	});
	/*190718수정 끝*/

});
