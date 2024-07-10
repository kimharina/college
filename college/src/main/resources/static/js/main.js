$(function(){

	// 상단배너
	$('.bannerWrap .close').on('click',function(e){
		$('.bannerWrap').slideUp();
		e.preventDefault();
	})


	// 페이지 로드 스크롤매직
	var controller = new ScrollMagic.Controller();
	new ScrollMagic.Scene({triggerElement: ".section1"})
		//.addIndicators()
		.setClassToggle(".section1", "active")
		//.reverse(false)
		.addTo(controller);
	new ScrollMagic.Scene({triggerElement: ".section2", offset: -300})
		//.addIndicators()
		.setClassToggle(".section2", "active")
		//.reverse(false)
		.addTo(controller);
	new ScrollMagic.Scene({triggerElement: ".section3", offset: -200})
		//.addIndicators()
		.setClassToggle(".section3", "active")
		//.reverse(false)
		.addTo(controller);
	new ScrollMagic.Scene({triggerElement: ".section4", offset: -200})
		//.addIndicators()
		.setClassToggle(".section4", "active")
		//.reverse(false)
		.addTo(controller);
	new ScrollMagic.Scene({triggerElement: ".section5", offset: -200})
		//.addIndicators()
		.setClassToggle(".section5", "active")
		//.reverse(false)
		.addTo(controller);
	new ScrollMagic.Scene({triggerElement: ".section6", offset: -200})
		//.addIndicators()
		.setClassToggle(".section6", "active")
		//.reverse(false)
		.addTo(controller); 

	//비주얼 
	// var $visualLst = $(".visualLst");
	// $progressBar = $(".visualWrap .progress");
	// $visualLst.slick({
	// 	infinite: true,
	// 	autoplay: true,
	// 	speed: 500,
	// 	slider: '.visual',
	// 	pauseOnHover:false,
	// 	slidesToShow: 1,
	// 	slidesToScroll: 1,
	// 	autoplaySpeed: 5000,
	// 	arrows: false,
	// 	dots: true,
	// 	dotsClass:'visualDots',
	// 	adaptiveHeight: true
	// 	//prevArrow: $('#gallPrev'),
	// 	//nextArrow: $('#gallNext'),
	// }).slick('setPosition');

	var $visualLst = $(".visualLst");
	$progressBar = $(".visualWrap .progress");
	$visualLst.slick({
		infinite: true,
		autoplay: true,
		speed: 500,
		slider: '.visual',
		pauseOnHover:false,
		slidesToShow: 1,
		slidesToScroll: 1,
		autoplaySpeed: 4000,
		arrows: false,
		dots: true,
		dotsClass:'visualDots',
		adaptiveHeight: true
		//prevArrow: $('#gallPrev'),
		//nextArrow: $('#gallNext'),
	}).on('afterChange', function() {
    	$('.visualWrap .visualLst .visualDots li button').attr('title','');  //페이징 타이틀 추가
        $('.visualWrap .visualLst .visualDots li.slick-active button').attr('title','메인이미지의 ' + $('.visualWrap .visualLst .visualDots li.slick-active button').html()+ ' 번째 탭 선택됨'); //페이징 타이틀 추가
    });  
    
	
	$('.visualWrap .control > a.slick_arr').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $visualLst, '#visualStop', '#visualPlay');
	});
	//비주얼 progress bar set
	var slideNum = $(".visualWrap .visualLst .visual.slick-active").length;
	var slideAll = $(".visualWrap .visualLst .visual").length;
	var calcNum = ((slideNum + 1) / (slideAll)) * 100;
	$progressBar.css("width", calcNum + "%").attr("aria-valuenow", calcNum);
	$visualLst.on("beforeChange", function(event, slick, currentSlide, nextSlide) {
		var calc = ((nextSlide + 1) / (slick.slideCount)) * 100;
		$progressBar.css("width", calc + "%").attr("aria-valuenow", calc);
	}); 
	
	// Tab
	$('.tab > li > a').on('click', function(e){
		$(this).parent().addClass('active').siblings().removeClass('active');
		$(this).parent().parent().find('> li > a').attr('title', "");
		$(this).attr('title', "선택됨");
		e.preventDefault();
	});

	//학사일정
	var $calendarLst = $(".calendarLst");
	$calendarLst.on('init', function(event, slick){
		$(".calendarLst .item:nth-of-type(even)").addClass('active');
	});
	$calendarLst.slick({
		variableWidth:true,
		infinite: true,
		autoplay: true,
		slider: '.item',
		slidesToShow: 3,
		slidesToScroll: 1,
		autoplaySpeed: 3000,
		pauseOnHover:false,
		arrows: true,
		adaptiveHeight: true,
		prevArrow: $('#calendarPrev'),
		nextArrow: $('#calendarNext'),
		responsive: [{
		  breakpoint: 1600,
		  settings: {
			slidesToShow: 3
		  }
		},
		{
		  breakpoint: 768,
		  settings: {
			slidesToShow: 2
		  }
		}, {
		  breakpoint: 480,
		  settings: {
			slidesToShow: 1
		  }
		}]
	}).slick('setPosition');
	$calendarLst.on('beforeChange', function(event, slick, currentSlide, nextSlide){
		$(".calendarLst .item").removeClass('active');
	});
	$('.calendarWrap .control > a.slick_act').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $calendarLst, '#calendarStop', '#calendarPlay');
	});
	$calendarLst.on('afterChange', function(event, slick, currentSlide){
		$(".calendarLst .item:nth-of-type(even)").addClass('active');
	});

	//팝업존
	var $popLst = $(".popLst");
	$popLst.each(function() {
		var $this = $(this);
		$popLst.on('init', function(event, slick) {
			$(".popWrap .counter").append('<strong class="current"></strong><span class="total"></span>');
			$(".popWrap .current").text((slick.currentSlide + 1) < 10 ? ((slick.currentSlide + 1)) : (slick.currentSlide + 1));
			$(".popWrap .total").text((slick.slideCount < 10 ? (slick.slideCount) : slick.slideCount));
			}).on('beforeChange', function(event, slick, currentSlide, nextSlide) {
			$(".popWrap .current").text((nextSlide + 1) < 10 ? ((nextSlide + 1)) : (nextSlide + 1));
		});
	});
	$popLst.slick({
		infinite: true,
		autoplay: true,
		slider: '.item',
		slidesToShow: 1,
		slidesToScroll: 1,
		autoplaySpeed: 3000,
		pauseOnHover:false,
		arrows: true,
		adaptiveHeight: true,
		prevArrow: $('#popPrev'),
		nextArrow: $('#popNext')
	}).slick('setPosition');
	$('.popWrap .control > a.slick_act').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $popLst, '#popStop', '#popPlay');
	});

	//포토뉴스
	var $photoLst = $(".photoLst");
	$photoLst.slick({
		infinite: true, 
		autoplay: true,
		slider: '.item',
		slidesToShow: 3,
		slidesToScroll: 1,
		autoplaySpeed: 3000,
		pauseOnHover:false,
		arrows: true,
		adaptiveHeight: true,
		prevArrow: $('#photoPrev'),
		nextArrow: $('#photoNext'),
		responsive: [{
		  breakpoint: 1025,
		  settings: {
			slidesToShow: 1
		  }
		}]
	}).slick('setPosition');
	$('.photoWrap .control > a.slick_act').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $photoLst, '#photoStop', '#photoPlay');
	});


	//부서 홈페이지
	var $webLst = $(".webLst");
	$webLst.each(function() {
		var $this = $(this);
		$webLst.on('init', function(event, slick) {
			$(".webWrap .counter").append('<strong class="current"></strong><span class="total"></span>');
			$(".webWrap .current").text((slick.currentSlide + 1) < 10 ? ((slick.currentSlide + 1)) : (slick.currentSlide + 1));
			$(".webWrap .total").text((slick.slideCount < 10 ? (slick.slideCount) : slick.slideCount));
			}).on('beforeChange', function(event, slick, currentSlide, nextSlide) {
			$(".webWrap .current").text((nextSlide + 1) < 10 ? ((nextSlide + 1)) : (nextSlide + 1));
		});
	});
	$webLst.slick({
		infinite: true,
		autoplay: true,
		slider: '.item',
		slidesToShow: 4,
		slidesToScroll: 1,
		speed: 400,
		autoplaySpeed: 2000,
		pauseOnHover:false,
		arrows: true,
		adaptiveHeight: true,
		prevArrow: $('#webPrev'),
		nextArrow: $('#webNext'),
		responsive: [{
		  breakpoint: 1400,
		  settings: {
			slidesToShow: 3
		  }
		}, {
		  breakpoint: 1160,
		  settings: {
			slidesToShow: 2
		  }
		}, {
		  breakpoint: 768,
		  settings: {
			slidesToShow: 1
		  }
		}]
	}).slick('setPosition');
	$('.webWrap .control > a.slick_act').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $webLst, '#webStop', '#webPlay');
	});
	 
	//학보
	var $newsLst = $(".newsLst");
	$newsLst.slick({
		infinite: true,
		autoplay: true,
		slider: '.item',
		slidesToShow: 3,
		slidesToScroll: 1,
		autoplaySpeed: 3000,
		pauseOnHover:false,
		arrows: true,
		adaptiveHeight: true,
		prevArrow: $('#newsPrev'),
		nextArrow: $('#newsNext'),
		responsive: [{
		  breakpoint: 1560,
		  settings: {
			slidesToShow: 2
		  }
		}, {
		  breakpoint: 1240,
		  settings: {
			slidesToShow: 1
		  }
		}]
	}).slick('setPosition');
	$('.newsWrap .control > a.slick_act').click(function(e) {
		e.preventDefault();
		$this = $(this);
		slickControl($this, $newsLst, '#newsStop', '#newsPlay');
	});
	

	var subTitelBox = $('.subTitleBox');
		subBtn = subTitelBox.find('.subTitle');
		subScroll = subTitelBox.find('.scroll');
		subColse = subTitelBox.find('.close');
 
	//교육방송국
	subBtn.on('click',function(e){ 
		subTitelBox.toggleClass('open');

		if (subTitelBox.hasClass('open')){
			subBtn.attr('title','자막닫기');
			subBtn.on('focusout',function(){
				subScroll.attr('tabindex','1').focus();
			});
		}else{
			subBtn.attr('title','자막펼치기');
		}; 
		e.preventDefault();
	});
	subScroll.on('focusout',function(){
		$(this).attr('tabindex','0');
		subColse.focus();
	});
	subColse.on('click',function(e){ 
		subTitelBox.removeClass('open')
		subBtn.attr('title','자막펼치기');
		e.preventDefault();
	});
});

function TabBox(div, tit) {
    $tab = $('.' + div);

    $tab.find(tit).each(function () {
        $(this).find('a').on("focus click", function (e) {
            e.preventDefault(); //상단이동방지

            $(this).parent(tit).siblings('.list_box').removeClass('on');
            $(this).parent(tit).siblings().find('> a').removeClass('current');
            $(this).parent(tit).next('.list_box').addClass('on');
            $(this).addClass('current');
        });
    });
}

// slider Control
function slickControl($this, slick, stop, play) {
    $slick = $(slick); //slider wrap
    $stop = $(stop); //Stop Button
    $play = $(play); //Play Button
    var display = $this.css("display"); // button's display

    if ($this.is(stop)) {
        $stop.css('display', 'none');
        $play.delay(100).css('display', display);
        $slick.slick('slickPause');
    }
    if ($this.is(play)) {
        $play.css('display', 'none');
        $stop.delay(100).css('display', display);
        $slick.slick('slickPlay');
    }
}
