$(function() {	
});
//Tab Control
function swTab(){
	$(".sw-tabs").each(function() {
		var $tab = $(this).find(" > li"),
			$tabBody = $(this).next(".sw-tab-contents");
		$tab.click(function(e){
		    if (!$(this).hasClass("is-active")) {
		        $(this).addClass("is-active").siblings().removeClass("is-active");
		        $("#"+$(this).data("id")).addClass("is-active").siblings().removeClass("is-active");
		    }
		});		
	});	
}
function moveTo(url) {
	document.location.href=url;
}

//Popup
function windowOpen(url, title, w, h) {
    var dualScreenLeft = window.screenLeft != undefined ? window.screenLeft : screen.left;
    var dualScreenTop = window.screenTop != undefined ? window.screenTop : screen.top;
 
    var width = window.innerWidth ? window.innerWidth : document.documentElement.clientWidth ? document.documentElement.clientWidth : screen.width;
    var height = window.innerHeight ? window.innerHeight : document.documentElement.clientHeight ? document.documentElement.clientHeight : screen.height;
 
    var left = ((width / 2) - (w / 2)) + dualScreenLeft;
    var top = ((height / 2) - (h / 2)) + dualScreenTop;
    var newWindow = window.open(url, title, 'scrollbars=yes, resizable=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);
    try{
    	parent.top.arrPop.push(newWindow);
    }catch(err){}
    if (window.focus) {
        newWindow.focus();
    }
}
function windowClose(){
	window.open('', '_self').close(); 
}
/*
 * jquery-confirm Dialog
 * parameter : 알림메세지, obj (function name)
 */
function fnAlert(argMsg, obj, lang, webgbn, icon){
	lang    = (lang == undefined ? "KOR" : lang);
	let btnText = (lang == "ENG" ? "O K" : "확 인");
	let title = (lang == "ENG" ? "Notice" : "알림");
	let boxWidth= (webgbn == undefined || webgbn=="W" ? "400" : "90%");
	let msg;
	try{
		msg = argMsg.replace(/\r|\n|\\n/gi,"<br>");
	}catch(err){
		msg = argMsg;
	}
	$.alert({
		title: title,
		content: "<p>"+msg+"<p>",
		closeIcon: (icon == false ? false : true),
		boxWidth:boxWidth,
		buttons: {
	        ok: {
	            text: btnText,
	            keys: ['enter'],
	            btnClass: 'btn-main',
	            action: function(){
	            	if(typeof obj == 'function'){
	    				obj();
	    			}
	            }
	        }
	    }
	});
}
/*
 * 저장, 삭제시 컨펌 Dialog
 * parameter : 과목명, 파라미터, rowid, mode
 */
function fnModeConfirm(lec_nm,params,rowid, mode, lang){
	lang    = (lang == undefined ? "KOR" : lang);
	let title = (lang == "ENG" ? "Notice" : "알림");
	let btnText1 = "확 인";
	let btnText2 = "취 소";
	let temp = (mode == "insert") ? "신청":"삭제";
	let msg = "["+lec_nm+ "]을 " + temp + " 하시겠습니까?";
	if(lang == "ENG"){
		btnText1 = "O K";
		btnText2 = "Cancel";
		temp = (mode == "insert") ? "register":"delete";
		msg = "Are you sure "+temp+" [" + lec_nm+"]?"
	}	
	$.alert({	    
		title: title,
		content: '<i class="sw-alert-info"></i>'+msg,
		closeIcon: true,
	    //boxWidth: '30%',
	    useBootstrap: false,
	    buttons:[
			    	{
			    		text: btnText1,
			    		keys: ['enter'],
			    		btnClass: 'btn-main btn-mode',
			    		open: function() {},
			    		action: function() { 
			    			fnCallMode(lec_nm,params,rowid, mode);
						}
			    	},
					{
						text: btnText2,
						btnClass: 'btn-cancel',
						action: function() {
							NetFunnel_Complete();
						}
					}
			    ]
	});
}
/*
 * jquery-confirm 컨펌 Dialog
 * parameter : 과목명, 파라미터, rowid, mode
 */
function fnComConfirm(argMsg, obj, lang){
	lang    = (lang == undefined ? "KOR" : lang);
	let title = (lang == "ENG" ? "Notice" : "알림");
	let btnText1 = "확 인";
	let btnText2 = "취 소";
	let msg;
	try{
		msg = argMsg.replace(/\r|\n|\\n/gi,"<br>");
	}catch(err){
		msg = argMsg;
	}
	
	if(lang == "ENG"){
		btnText1 = "O K";
		btnText2 = "Cancel";
	}
	 $.alert({
		title: title,
		content: '<i class="sw-alert-info"></i>'+msg,
		closeIcon: true,
	    buttons: [
					{
						text: btnText1,
						keys: ['enter'],
			    		btnClass: 'btn-main',
						open: function() {},
						action: function() { 
							if(typeof obj == 'function'){
		        				obj();
		        			}
						}
					},
					{
						text: btnText2,
						btnClass: 'btn-cancel',
						action: function() { 
						}
					}
				]
	});// end dialog
}
function getContextPath() {
	var hostIndex = location.href.indexOf( location.host ) + location.host.length;
	return location.href.substring( hostIndex, location.href.indexOf("/", hostIndex + 1));
}
//min (포함) 과 max (불포함) 사이의 임의 정수를 반환
//Math.round() 를 사용하면 고르지 않은 분포를 얻게된다!
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min)) + min;
}
/* 금액 콤마 표시 */
function addComma(x) {
    return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
$.fn.hasScrollBar = function() {
    return (this.prop("scrollHeight") == 0 && this.prop("clientHeight") == 0)
            || (this.prop("scrollHeight") > this.prop("clientHeight"));
};
String.prototype.startsWith = function(str) {
	if (this.length < str.length) { return false; }
	return this.indexOf(str) == 0;
}
String.prototype.endsWith = function(str) {
	if (this.length < str.length) { return false; }
	return this.lastIndexOf(str) + str.length == this.length;
}
function fnObjFocus(obj){
	setTimeout(function(){obj.focus()},300);
}
var setCookies = function(name, value, exp) {
  var today = new Date();
  //today.setTime(today.getTime() + exp*24*60*60*1000);
  today.setDate(today.getDate() + exp);
  document.cookie = name + '=' + escape( value ) + ';expires=' + today.toGMTString() + ';path=/';
};
var getCookies = function(name) {
  var value = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
  return value? value[2] : null;
};