/**
 * comm.js 업무를 제외한 시스템 공통 javascript.
 * 
 */

// null체크용. util.js와의 의존성을 제거하기 위해 만든 내부 함수.
var __fn_comm_nvl = function(objValue, defValue) {
	return (objValue == null || objValue == undefined) ? defValue : objValue;
};

/**
 * 해당 폼의 내용들을 JSON 형태로 반환합니다. classDivider 를 주지 않으면, 다음과 같은 형식의 JSON 객체가 반환됩니다.
 * 이 경우 disabled 된 요소는 제외됩니다. classDivider 를 주면, 폼 내부에서 classDivider 선택자를 검사하여,
 * 검사 결과 각각의 내부의 폼 요소들의 값들을 담은 JSON 객체들의 배열이 반환됩니다. 이 경우는 disabled 된 요소가 포함됩니다.
 * 
 * @param selector :
 *            폼 선택자 (ex: #frm), classDivider 사용 시 궂이 form 요소를 사용할 필요는 없으나, 선택
 *            결과가 고유하도록 사용하는 것을 권장, classDivider 사용 안할 시 반드시 form 요소 사용
 * @param classDivider :
 *            폼 내부 단위 구분용 선택자 (ex: .FORM_BLOCK_ELEMENT)
 */
function fn_comm_jsonFromForm(selector, classDivider) {
	if (classDivider) { // 다건(동적으로)인 경우 (form은 하나)
		var resultList = [];
		var $_unitDiv = null;
		if (selector == classDivider)
			$_unitDiv = $(selector); // 폼 선택자와 단위 구분 선택자가 같은 경우에 적용 (disabled
										// 된 요소를 포함시키기 위해 일부러 이렇게 호출한 경우)
		else
			$_unitDiv = $(selector).find(classDivider);
		$_unitDiv.each(function() {
			var newObj = {};
			$(this).find("input, select, textarea").each(function() { // 폼 요소
																		// 검사
				var element = this;
				if ($(this).is("[type='checkbox']")) { // 체크박스의 경우 (값이 다수일 수 있음
														// !)
					if ($(this).is(':checked')) { // 체크되어 있으면
						if (newObj[element.name])
							newObj[element.name].push(this.value); // 배열이 만들어져
																	// 있으면 --> 값
																	// 추가
						else
							newObj[element.name] = [ this.value ]; // 배열이 만들어져
																	// 있지 않으면
																	// --> 배열
																	// 만들고 값 삽입
					} else if (!newObj[element.name])
						newObj[element.name] = []; // 체크되지 않았지만 배열이 만들어져 있지 않으면
													// --> 빈 배열 생성
				} else if ($(this).is("[type='radio']")) { // 라디오 버튼의 경우
					if ($(this).is(':checked'))
						newObj[element.name] = this.value; // 선택되어 있으면 --> 값 삽입
					else if (!newObj[element.name])
						newObj[element.name] = null; // 선택되지 않았지만 값이 만들어져 있지
														// 않으면 --> null 삽입
														// (undefined 방지)
				} else if ($(this).is("select")) { // 콤보박스 / 리스트의 경우
					if ($(this).is("[size]")) { // size 속성이 있으면 --> 다건 선택 가능
						$(this).find('option').each(function() { // option
																	// 요소들 찾음
							if (this.is(':selected')) { // 선택되어 있으면
								if (newObj[element.name])
									newObj[element.name].push(this.value);
								else
									newObj[element.name] = [ this.value ];
							} else if (!newObj[element.name])
								newObj[element.name] = [];
						});

					} else
						newObj[element.name] = this.value; // 다건 선택 안해도 되므로 값
															// 삽입
				} else
					newObj[element.name] = this.value; // 그 외의 폼 요소 --> 값 삽입
			});
			resultList.push(newObj);
		});
		return resultList;
	} else { // 단건일 경우
		var nextObjArr = $(selector).serializeArray();
		var nextObj = {};

		// 배열 형태를 JSON 형태로 변환
		for (var idx = 0; idx < nextObjArr.length; idx++) {
			if (nextObj[nextObjArr[idx].name]) {
				if ($.isArray(nextObj[nextObjArr[idx].name])) {
					nextObj[nextObjArr[idx].name].push(nextObjArr[idx].value);
				} else {
					var beforeObj = nextObj[nextObjArr[idx].name];
					nextObj[nextObjArr[idx].name] = [];
					nextObj[nextObjArr[idx].name].push(beforeObj);
					nextObj[nextObjArr[idx].name].push(nextObjArr[idx].value);
				}
			} else
				nextObj[nextObjArr[idx].name] = nextObjArr[idx].value;
		}
		return nextObj;
	}
}

$.fn.fn_comm_serializeObject = function() {
	var obj = {};
	var arr = this.serializeArray();
	$.each(arr, function() {
		if (obj[this.name] !== undefined) {
			if (!$.isArray(obj[this.name])) {
				obj[this.name] = [ obj[this.name] ];
			}
			obj[this.name].push(this.value);
		} else {
			obj[this.name] = this.value;
		}
	});
	return obj;
};

var __ajax_count__ = 0;

var fn_comm_showProgressbar = function() {
	if (__ajax_count__ == 0) {
		if ($("#div_comm_progressbarDialog").length == 0) {
			$("body")
					.append(
							"<div id='div_comm_progressbarDialog' style='display:none;'><div id='div_comm_progressbar'></div></div>");
			if (typeof $("#div_comm_progressbar").progressbar == 'function')
				$("#div_comm_progressbar").progressbar({
					value : false
				});
		}
		if (typeof $("#div_comm_progressbarDialog").dialog == 'function')
			$("#div_comm_progressbarDialog").dialog({
				modal : true,
				title : "잠시만 기다리세요",
				height : 100
			});
	}
	++__ajax_count__;
};

var fn_comm_hideProgressbar = function() {
	--__ajax_count__;
	if (__ajax_count__ <= 0
			&& typeof $("#div_comm_progressbarDialog").dialog == 'function') {
		$("#div_comm_progressbarDialog").dialog("close");
		__ajax_count__ = 0;
	}
};

/**
 * ajax 공통함수. jQuery의 argument는 ajax 함수와 같음.
 * 
 * @param {}
 *            url
 * @param {}
 *            options success, error 콜백 함수를 가로채서 처리함. parentIdForSetByName 옵션을
 *            설정하면 success일 경우 parentIdForSetByName 값으로 노드를 찾은 후 자식 노드의 name값이
 *            json data 값과 일치하면 값을 설정함. input 요소의 경우 val()함수를 호출하고 나머지는 text()
 *            함수 호출함. 파일 업로드 사용시 options에 ajaxFormName 추가 (예 : ajaxFormName :
 *            "frm")
 */
var fn_comm_ajax = function(url, options) {
	// If url is an object, simulate pre-1.5 signature
	if (typeof url === "object") {
		options = url;
		url = undefined;
	}

	if (!options) {
		$.ajax(url);
		return;
	}

	if (!options.dataType) {
		options.dataType = "json";
	}

	// 검색조건 저장
	var pageId = options.pageId;
	if ((pageId != null && typeof (pageId) != 'undefined')
			&& options.data != null && typeof (options.data) != 'undefined') {
		// pageId 가 'auto' 이면 svcName 사용 (sub_template, popup_template 상단에 정의됨)
		if (pageId == 'auto') {
			if (svcName == null || typeof (svcName) == 'undefined') {
				throw "svcName 을 가져오지 못했습니다. pageId 를 수동으로 지정해야 합니다.";
			}
			pageId = svcName;
		}
		fn_util_setCookie('PAGE_' + pageId, JSON
				.stringify(fn_util_jsonFromGet(options.data)), null, '/');
	}

	if (options.success) {
		options._success = options.success;
	}
	options.success = this.fn_comm_ajaxSuccess;

	if (options.error) {
		options._error = options.error;
	}
	options.error = this.fn_comm_ajaxError;

	options.beforeSend = function(jqXHR, settings) {
		jqXHR._success = settings._success;
		jqXHR._error = settings._error;

		if (settings.parentIdForSetByName) {
			jqXHR.parentIdForSetByName = settings.parentIdForSetByName;
		}
	};

	fn_comm_showProgressbar();

	// 09.11 starworld
	options.type = "POST";

	if (options.ajaxFormName) {
		if ($.isPlainObject(options.data) || options.date == null) {
			options.type = "POST";
			$("#" + options.ajaxFormName)
					.attr("enctype", "multipart/form-data");
			$("#" + options.ajaxFormName).attr("action", url);
			$("#" + options.ajaxFormName).ajaxForm(options);
			$("#" + options.ajaxFormName).submit();
		} else {
			throw "options.data형식은 json형식이여야 합니다.";
		}

	} else {
		return $.ajax(url, options);
	}

};

var fn_comm_ajaxSuccess = function(data, textStatus, jqXHR) {
	if (jqXHR.parentIdForSetByName) {
		fn_comm_setValue(jqXHR.parentIdForSetByName, data.data);
	}

	fn_comm_hideProgressbar();
	if (jqXHR._success) {
		jqXHR._success.apply(this, [ data.data, textStatus, jqXHR ]);
	}
};

this.fn_comm_ajaxError = function(jqXHR, textStatus, errorThrown) {
	fn_comm_hideProgressbar();

	var errmsg = "시스템에 오류가 발생했습니다.\n[오류메세지]\n" + textStatus + "\n"
			+ errorThrown + "\n" + jqXHR.responseText;
	if (jqXHR._error) {
		jqXHR._error.apply(this, [ jqXHR, textStatus, errorThrown ]);
		return;
	}

	var jsonStr = jqXHR.responseText;
	var jsonObj = null;
	try {
		jsonObj = $.parseJSON(jsonStr);
	} catch (e) {
		alert(errmsg);
		return;
	}
	errmsg = jsonObj.alertmsg;
	if (errmsg != undefined) {
		alert(errmsg);
		return;
	}
	errmsg = jsonObj.errmsg;
	errmsg = errmsg.replace("java.lang.RuntimeException: ", "");
	if (svcMode == "LOCAL") {
		alert(errmsg);
	} else {
		location.href = contextPath + "/code500.jsp?comm_error_DOMAIN_CD="
				+ encodeURIComponent(domainCd) + "&errmsg="
				+ encodeURIComponent(errmsg);
	}
};

var fn_comm_processScalarAjax = function(url, options) {
	// If url is an object, simulate pre-1.5 signature
	if (typeof url === "object") {
		options = url;
		url = undefined;
	}

	if (!options) {
		options = {
			url : url,
			async : false,
			dataType : "text"
		};
	} else {
		options.async = false;
		options.dataType = "text";
	}

	if (options.success) {
		options._success = options.success;
	}
	options.success = this.fn_comm_processScalarAjaxSuccess;
	if (options.error) {
		options._error = options.error;
	}
	options.error = this.fn_comm_ajaxError;
	options.beforeSend = function(jqXHR, settings) {
		jqXHR._success = settings._success;
		jqXHR._error = settings._error;
	};

	var returnData = null;
	options.complete = function(jqXHR, textStatus) {
		returnData = jqXHR.returnData;
	};

	fn_comm_showProgressbar();
	$.ajax(url, options);
	return returnData;
};

var fn_comm_processScalarAjaxSuccess = function(data, textStatus, jqXHR) {
	fn_comm_hideProgressbar();
	if (data != undefined || data != null)
		data = data.replace(/\"/g, "");
	jqXHR.returnData = data;
	if (jqXHR._success) {
		jqXHR._success.apply(this, [ data, textStatus, jqXHR ]);
	}
};

/**
 * input element 및 기타 element에 값 대입. select 태그의 multiple 경우는 고려 안함;;
 * 
 * @param {}
 *            $_parent
 * @param {}
 *            jsonObj
 */
var fn_comm_setValue = function(parentIdForSetByName, jsonObj) {
	$(parentIdForSetByName).fn_comm_setValue(jsonObj);
};

/**
 * input element 및 기타 element에 값 대입. select 태그의 multiple 경우는 고려 안함;;
 * 
 * @param {}
 *            $_parent
 * @param {}
 *            jsonObj
 */
$.fn.fn_comm_setValue = function(jsonObj) {
	return this.each(function(index, element) {
		var $_parent = $(element);
		for ( var elementName in jsonObj) {
			//if("CONTENTS" == elementName) continue;
			var $_element = $_parent.find("[name='" + elementName + "']");
			if ($_element.length == 0)
				continue;
			var value = jsonObj[elementName];
			value = __fn_comm_nvl(value, "");

			if ($.isArray(value)) { // 배열인 경우
				// 체크박스, 라디오의 경우
				$_element.filter(":checkbox,:radio").val(value);

				// 그 외의 경우
				if (value.length == 0) {
					// input 요소 -> .val()로 대입
					$_element.filter(":input:not(:checkbox,:radio)").val("");
					// text 요소 -> .text()로 대입
					$_element.filter(":not(:input)").html("");
				} else {
					// input 요소 -> .val()로 대입
					$_element.filter(":input:not(:checkbox,:radio)").val(fn_util_htmlDecode(value[0]));
					// text 요소 -> .text()로 대입
					$_element.filter(":not(:input)").html(fn_util_htmlEncode(value[0]));
				}
			} else { // 배열이 아닌 경우
				// input:checkbox,radio 요소 -> .val([])로 대입
				$_element.filter(":checkbox,:radio").val([ value ]);
				// input 요소 -> .val()로 대입
				$_element.filter(":input:not(:checkbox,:radio)").val(fn_util_htmlDecode(value));
				// text 요소 -> .text()로 대입
				$_element.filter(":not(:input)").html(fn_util_htmlEncode(value));
			}
		}
	});
};
/**
 * 쿠키로부터 저장된 검색조건들을 받아 폼에 적용합니다.
 * 
 * pageId 를 지정하지 않으면 서비스 이름을 사용합니다.
 */
var prevPageId;
$.fn.fn_comm_setFromCookie = function(pageId) {
	if(prevPageId != pageId){
		prevPageId = pageId;
		return;
	}
	// 페이지 ID를 지정하지 않은 경우 --> svcName 사용 (sub_template, popup_template 상단에 정의되어
	// 있음)
	if (pageId == null && (svcName != null && typeof (svcName) != 'undefined'))
		pageId = svcName;

	var cookieJSON = fn_util_getCookie('PAGE_' + pageId);
	if (cookieJSON == null || typeof (cookieJSON) == 'undefined'
			|| fn_util_isEmpty(cookieJSON))
		return;
	var jsonObj = JSON.parse(cookieJSON);
	$(this).fn_comm_setValue(jsonObj);
};

/**
 * list에 값 대입. jquery template 사용. id값은 #을 붙여서 사용 바람. paginationId 값이 있으면 페이징
 * 결과라 생각하고 data.list를 기준으로 출력함. (paging처리 리스트인데 페이지 번호를 사용 안할리는 없잖아...?)
 * 
 * @param {}
 *            parentId. 보통... tbody. table, ul, ol 등등 부모 selector값
 * @param {}
 *            data
 * @param ...
 */
var fn_comm_setList = function(parentId, data, dataTemplateId,
		noDataTemplateId, rowCountId, paginationId, cb) {
	$(parentId).fn_comm_setList(data, dataTemplateId, noDataTemplateId,
			rowCountId, paginationId, cb);
};

$.fn.fn_comm_setList = function(data, dataTemplateId, noDataTemplateId,
		rowCountId, paginationId) {
	var isPaging = !fn_comm_isNull(paginationId);
	var list = null;
	if (isPaging) {
		if (typeof data.list == "undefined") {
			list = data;
		} else {
			list = data.list;
		}
	} else {
		list = data;
	}
	this.empty();
	if (list == null || list.length == 0) {
		if (rowCountId) {
			$(rowCountId).text(0);
		}
		if (noDataTemplateId) {
			$(noDataTemplateId).tmpl({}).appendTo(this);
		}
		if (isPaging) {
			$(paginationId).html("");
		}
		return;
	}

	if (rowCountId) {
		var cnt = 0;
		if (isPaging) {
//			var cntVal = String(list[0]["__CNT__"]);
			var cntVal = String(data.totalRecordCount);
			if (!fn_util_isEmpty(cntVal))
				cnt = Number(cntVal);
		} else {
			cnt = list.length;
		}
		cnt = fn_util_makeComma(cnt);
		$(rowCountId).text(cnt);
	}
	for (var idx = 0; idx < list.length; idx++) {
		var dataObj = list[idx];
		if (isPaging) {
			dataObj.rownum = dataObj["__RNUM__"];
		} else {
			dataObj.rownum = (idx + 1);
		}
	}
	$(dataTemplateId).tmpl(list).appendTo(this);
	if (isPaging) {
		
		$.ajax({
            url: "/bvs/pagingF.do",
            data : {
                currentPageNo : data.currentPageNo,
                totalRecordCount : data.totalRecordCount,
                recordCountPerPage : data.recordCountPerPage,
                paginationJsFunction : data.jsFunction
            },
            type : "POST",
            success : function(data) {
            	$(paginationId).html(data);
            }
        });
	}
	if (typeof applyDotdotdot == 'function') {
		applyDotdotdot();
	}
};

/*
 * table merge 출처 :
 * http://willifirulais.blogspot.kr/2007/07/jquery-table-column-break.html 등등..
 * 상위행 기준으로 merge. 하위행은 삭제됨.
 */
$.fn.rowspan = function(colIdx, stdColIdx) {
	stdColIdx = __fn_comm_nvl(stdColIdx, colIdx);
	return this.each(function() {
		var that = null;
		var stdThat = null;
		$('tr', this).each(
				function(row) {
					var $_td = $('>:eq(' + colIdx + ')', this).filter(
							':visible');
					var $_stdTd = $('>:eq(' + stdColIdx + ')', this).filter(
							':visible');
					$_td.each(function(col) {
						var stdThis = $_stdTd.filter(':eq(' + col + ')')[0]; // stdThis=td:stdColIdx
						if ($(stdThis).html() == $(stdThat).html()) { // this=td:colIdx
							var rowspan = $(stdThat).attr('rowspan') || 1;
							rowspan = Number(rowspan) + 1;
							$(stdThat).attr('rowspan', rowspan); // do your
																	// action
																	// for the
																	// colspan
																	// cell here
							$(that).attr('rowspan', rowspan); // do your
																// action for
																// the colspan
																// cell here
							$(this).hide(); // .remove(); // do your action for
											// the old cell here
							$(stdThis).hide(); // .remove(); // do your action
												// for the old cell here
						} else {
							that = this;
							stdThat = stdThis;
						}
						that = (that == null) ? this : that; // set the that
																// if not
																// already set
						stdThat = (stdThat == null) ? stdThis[0] : stdThat; // set
																			// the
																			// that
																			// if
																			// not
																			// already
																			// set
					});
				});
	});
};

$.fn.rowspanByAttr = function(colIdx, stdAttr) {
	return this.each(function() {
		var that = null;
		var td = null;
		var rowCnt = $('tr', this).length;
		for (var idx = 0; idx < rowCnt; idx++) {
			td = $('tr:eq(' + idx + ')>:eq(' + colIdx + ')', this);
			if (td.attr(stdAttr) != null) {
				if (td.attr(stdAttr) == $(that).attr(stdAttr)) {
					var rowspan = $(that).attr('rowspan') || 1;
					rowspan = Number(rowspan) + 1;
					$(that).attr('rowspan', rowspan); // do your action for
														// the colspan cell here
					td.hide(); // .remove(); // do your action for the old cell
								// here
				} else {
					that = td;
				}
				that = (that == null) ? td : that; // set the that if not
													// already set
			}
		}
	});
};

$.fn.colspan = function(rowIdx) {
	return this.each(function() {
		var that = null;
		$('tr:eq(' + rowIdx + ')', this).each(function(row) {
			$(this).find('td,th').filter(':visible').each(function(col) {
				if ($(this).html() == $(that).html()) {
					var colspan = $(that).attr('colspan') || 1;
					colspan = Number(colspan) + 1;
					$(that).attr("colspan", colspan);
					$(this).hide(); // .remove();
				} else {
					that = this;
				}
				that = (that == null) ? this : that; // set the that if not
														// already set
			});
		});
	});
};
/* table merge */

/* table sum */
$.fn.sum = function(colIdx, expr, cls, total) {
	var sumValue = 0;
	this.each(function() {
		$('tr', this).each(function(row) {
			$('td:eq(' + colIdx + ')', this).each(function(col) {
				var val = 0;
				if (cls == null) {
					val = new Number($(this).text()); // parseInt($(this).text());
				} else {
					val = new Number($(this).find(cls).text()); // parseInt($(this).text());
				}

				if (isNaN(val))
					val = 0;
				sumValue += val;
			});
		});
	});
	if (expr) {
		$(expr).text(sumValue);
	}
	return sumValue;
};
/* table sum */
/* table avg */
$.fn.avg = function(colIdx, expr, dcmPoint) {
	var sumValue = 0;
	var avgValue = 0;
	var rowCnt = $('tr', this).length - 1;
	this.each(function() {
		$('tr', this).each(
				function(row) {
					$('td:eq(' + colIdx + ')', this).filter(':visible').each(
							function(col) {
								var val = new Number($(this).text().replace(
										/%/gi, '')); // parseInt($(this).text());
								if (isNaN(val))
									val = 0;
								sumValue += val;
							});
				});
	});
	avgValue = new Number(new Number(sumValue / rowCnt).toFixed(dcmPoint));

	if (expr) {
		$(expr).text(avgValue + '%');
	}
	return avgValue;
};
/* table avg */

/* datepicker function hooking */

$.fn.__datepicker = $.fn.datepicker;
$.fn.datepicker = function() {
	var args = $.fn.datepicker.arguments;
	$_this = $(this);
	$_this.__datepicker.apply(this, args);
	$_this.next("a.btn_calendar,button.btn_calendar").click(function() {
		var $_dateInput = $(this).prev("input");
		if ($_dateInput.is(':disabled'))
			return;
		$_dateInput.triggerHandler("focus");
	});
};

/* datepicker function hooking */

(function(factory) {
	if (typeof define === "function" && define.amd) {
		// AMD. Register as an anonymous module.
		define([ "../jquery.ui.datepicker" ], factory);
	} else {
		// Browser globals
		factory(jQuery.datepicker);
	}
}(function(datepicker) {
	if (typeof datepicker != 'undefined') {
		datepicker.regional['ko'] = {
			closeText : '닫기',
			prevText : '이전',
			nextText : '다음',
			currentText : '오늘',
			monthNames : [ '1월', '2월', '3월', '4월', '5월', '6월', '7월', '8월',
					'9월', '10월', '11월', '12월' ],
			monthNamesShort : [ '1', '2', '3', '4', '5', '6', '7', '8', '9',
					'10', '11', '12' ],
			dayNames : [ '일', '월', '화', '수', '목', '금', '토' ],
			dayNamesShort : [ '일', '월', '화', '수', '목', '금', '토' ],
			dayNamesMin : [ '일', '월', '화', '수', '목', '금', '토' ],
			weekHeader : '주',
			dateFormat : 'yy-mm-dd',
			firstDay : 0,
			isRTL : false,
			showMonthAfterYear : true,
			yearSuffix : '년'
		};
		datepicker.setDefaults(datepicker.regional['ko']);
		return datepicker.regional['ko'];
	}
}));
/* datepicker function hooking */

/**
 * jQuery datepicker 옵션설정
 * 
 * @param domId :
 *            필수 DOM ID ex) "#FC_SEARCH_TYPE"
 * @param defaultdate
 *            기본값 0(현재날짜) 유형 : 날짜,숫자,문자 ex) 1d:1일후, 1m:1달후
 * @param changemonth
 *            기본값 true 달
 * @param dateformat
 *            기본값 yy-mm-dd -> yyyy-mm-dd 형태로 출력
 * @param callbackFunction
 * @deprecated
 */
var fn_calDate = function(domId, defaultdate, changemonth, dateformat,
		callbackFunction) {
	if (domId == null || domId == undefined) {
		return;
	}
	$(domId).fn_comm_datepicker(defaultdate, changemonth, dateformat,
			callbackFunction);
};

/**
 * jQuery datepicker 옵션설정
 * 
 * @param domId :
 *            필수 DOM ID ex) "#FC_SEARCH_TYPE"
 * @param defaultdate
 *            기본값 0(현재날짜) 유형 : 날짜,숫자,문자 ex) 1d:1일후, 1m:1달후
 * @param changemonth
 *            기본값 true 달
 * @param dateformat
 *            기본값 yy-mm-dd -> yyyy-mm-dd 형태로 출력
 * @param callbackFunction
 */
$.fn.fn_comm_datepicker = function(defaultdate, changemonth, dateformat,
		callbackFunction) {
	defaultdate = __fn_comm_nvl(defaultdate, "0");
//	changemonth = __fn_comm_nvl(changemonth, true);
	changemonth = true;
	dateformat = __fn_comm_nvl(dateformat, "yy-mm-dd");
	callbackFunction = __fn_comm_nvl(callbackFunction, '');

	this.datepicker({
		defaultDate : defaultdate,
		changeMonth : changemonth,
		dateFormat : dateformat,
		onClose : callbackFunction
	});
//	this.mask("9999-99-99", {
//		placeholder : "    -  -  "
//	});
};

/**
 * jQuery mask를 이용하여 시간입력 포맷 등록.
 * 
 * @param settings
 */
$.fn.fn_comm_maskTime = function(settings) {
	this.mask("99:99", settings);
	this.blur(function(eventObject) {
		var $_this = $(this);
		var timeReg = /^(([0-1][0-9])|(2[0-3])):[0-5][0-9]$/;
		if (!timeReg.test($_this.val())) {
			$_this.val("");
		}
	});
};

$.fn.fn_comm_maskInteger = function(mask) {
	$(this).css("text-align", "right");
	if (!fn_comm_isNull(mask)) {
		$(this).mask(mask);
	}
	$(this).blur(function(eventObject) {
		var $_this = $(this);
		var numReg = /[^0-9|^\-]/g;
		if (numReg.test($_this.val())) {
			$_this.val("");
		}
	});
};

$.fn.fn_comm_maskNumber = function(mask) {
	$(this).css("text-align", "right");
	if (!fn_comm_isNull(mask)) {
		$(this).mask(mask);
	}
	$(this).blur(function(eventObject) {
		var $_this = $(this);
		if (isNaN(Number($_this.val()))) {
			$_this.val("");
		}
	});
};

/* input 요소 생성 */
$.fn.fn_comm_makeSelect = function(options) {
	var arr = options.data; // 필수
	var url = options.url; // arr이 널일경우 필수
	var jsonName = options.jsonName; // 필수
	var jsonValue = options.jsonValue; // 필수
	var defaultText = options.defaultText;

	if (fn_comm_isNull(arr) && !fn_comm_isNull(options.url)) {
		fn_comm_ajax({
			url : url,
			async : false,
			dataType : "json",
			success : function(arrayData, textStatus, jqXHR) {
				arr = arrayData;
			}
		});
	}

	this.each(function(elementInJQueryIndex, element) {
		var $_element = $(element);
		if (element.tagName != "SELECT") {
			return;
		}
		if (defaultText != null && defaultText != undefined)
			$_element.append('<option value="">' + defaultText + '</option>');
		for (var idx = 0; idx < arr.length; idx++) {
			var data = arr[idx];
			$(
					'<option value="' + data[jsonName] + '">' + data[jsonValue]
							+ '</option>').appendTo($_element).data("data",
					data);
		}
	});
	if (options.callbackFunc) {
		options.callbackFunc.apply(this, [ arr ]);
	}
	return this;
};

$.fn.fn_comm_makeCheckbox = function(options) {
	var arr = options.data; // 필수
	var url = options.url; // arr이 널일경우 필수
	var jsonName = options.jsonName; // 필수
	var jsonValue = options.jsonValue; // 필수
	var elementName = __fn_comm_nvl(options.elementName, "");
	var prefix = __fn_comm_nvl(options.prefix, ""); // <span class="inputbox">
	var suffix = __fn_comm_nvl(options.suffix, ""); // </span>

	if (fn_comm_isNull(arr) && !fn_comm_isNull(options.url)) {
		fn_comm_ajax({
			url : url,
			async : false,
			dataType : "json",
			success : function(arrayData, textStatus, jqXHR) {
				arr = arrayData;
			}
		});
	}

	this.each(function(elementInJQueryIndex, element) {
		var $_element = $(element);
		for (var idx = 0; idx < arr.length; idx++) {
			var data = arr[idx];
			var $input = $(
					'<input type="checkbox" id="' + elementName
							+ data[jsonName] + '" name="' + elementName
							+ '" value="' + data[jsonName] + '"/>').data(
					"data", data);
			var $label = $(
					'<label for="' + elementName + data[jsonName] + '">'
							+ data[jsonValue] + '</label>' + suffix).appendTo(
					$_element).data("data", data);
			$label.insertBefore(prefix);
			$label.prepend($input);
		}
	});
	if (options.callbackFunc) {
		options.callbackFunc.apply(this, [ arr ]);
	}
	return this;
};

$.fn.fn_comm_makeRadio = function(options) {
	var arr = options.data; // 필수
	var url = options.url; // arr이 널일경우 필수
	var jsonName = options.jsonName; // 필수
	var jsonValue = options.jsonValue; // 필수
	var elementName = __fn_comm_nvl(options.elementName, "");
	var defaultText = options.defaultText;
	var prefix = __fn_comm_nvl(options.prefix, ""); // <span class="inputbox">
	var suffix = __fn_comm_nvl(options.suffix, ""); // </span>

	if (fn_comm_isNull(arr) && !fn_comm_isNull(options.url)) {
		fn_comm_ajax({
			url : url,
			async : false,
			dataType : "json",
			success : function(arrayData, textStatus, jqXHR) {
				arr = arrayData;
			}
		});
	}

	this.each(function(elementInJQueryIndex, element) {
		var $_element = $(element);
		if (defaultText != null && defaultText != undefined) {
			$_element.append(prefix + '<label for="' + elementName
					+ '_all"><input type="radio" id="' + elementName
					+ '_all" name="' + elementName
					+ '" value="" checked="checked" />' + defaultText
					+ '</label>' + suffix);
		}
		for (var idx = 0; idx < arr.length; idx++) {
			var data = arr[idx];
			var $input = $(
					'<input type="radio" id="' + elementName + data[jsonName]
							+ '" name="' + elementName + '" value="'
							+ data[jsonName] + '"/>').data("data", data);
			var $label = $(
					'<label for="' + elementName + data[jsonName] + '">'
							+ data[jsonValue] + '</label>' + suffix).appendTo(
					$_element).data("data", data);
			$label.insertBefore(prefix);
			$label.prepend($input);
		}
	});
	if (options.callbackFunc) {
		options.callbackFunc.apply(this, [ arr ]);
	}
	return this;
};
/* input 요소 생성 */

/* validation */
/**
 * 유효성 체크.
 * 
 * required="required" minlength="X" maxlength="X" 등등 form 요소에 attribute 설정해야함
 * 
 * @param options
 *            유효성체크 설정.
 * 
 * <pre>
 * var validationOptions = {
 * 	messages : {
 * 		LC_NM : &quot;자격증명을 입력하세요&quot; //json name: form 요소 id 또는 name, json value: 유효성 오류메세지
 * 	},
 * 	invalidCallbacks : {
 * 		LC_NM : function() { //json name: form 요소 id 또는 name, json value: 유효성 오류 발생시 실행할 함수
 * 			fn_P01();
 * 		}
 * 	}
 * };
 * $(&quot;#form&quot;).fn_comm_validate(validationOptions);
 * </pre>
 * 
 */
$.fn.fn_comm_validate = function(options) {
	var messages = (options && options.messages) ? options.messages : {};
	var invalidCallbacks = (options && options.invalidCallbacks) ? options.invalidCallbacks
			: {};
	var isValid = true;
	this.each(function(elementInJQueryIndex1, element1) { // form loop
		if (!isValid) // 한개만 체크
			return;

		var $_input = $(element1).find(":input");

		var alertInvalidMessage = function($_input2, msg, defaultMsg,
				invalidCallbacks) {
			var idOrName = $_input2.attr("id") || $_input2.attr("name");
			if (idOrName != undefined && msg[idOrName] != undefined) { // id가
																		// 있고
																		// id에
																		// 대한
																		// 메시지가
																		// 있을경우
				alert(msg[idOrName]);
				$_input2.focus();
			} else {
				alert(defaultMsg);
				$_input2.focus();
			}
			if (invalidCallbacks[idOrName]) {
				invalidCallbacks[idOrName].apply(this, [ $_input2 ]);
			}
		};
		// required
		$_input.filter("[required]").each(
				function(elementInJQuery2, element2) { // input loop
					if (!isValid) // 한개만 체크
						return;
					var $_input2 = $(element2);
					var val = $_input2.val();
					if (val == null || val == undefined || val == "") { // not
																		// null
																		// 체크.
																		// trim
																		// 할까
																		// 말까?
						alertInvalidMessage($_input2, messages,
								"필수 입력 항목을 확인하세요.", invalidCallbacks);
						isValid = false;
					}
				}); // input loop

		// minlength
		$_input.filter(":text[minlength],textarea[minlength]").each(
				function(elementInJQuery2, element2) { // input loop
					if (!isValid) // 한개만 체크
						return;
					var $_input2 = $(element2);
					var val = $_input2.val();
					var minlength = parseInt($_input2.attr("minlength"), 10);
					if (val == null || val == undefined
							|| fn_util_getByteLength(val) < minlength) { // length
																			// 체크.
						alertInvalidMessage($_input2, messages, minlength
								+ "자 이상 입력하세요.", invalidCallbacks);
						isValid = false;
					}
				}); // input loop

		// maxlength
		$_input.filter(":text[maxlength],textarea[maxlength]").each(
				function(elementInJQuery2, element2) { // input loop
					if (!isValid) // 한개만 체크
						return;
					var $_input2 = $(element2);
					var val = $_input2.val();
					var maxlength = parseInt($_input2.attr("maxlength"), 10);
					if (val == null || val == undefined
							|| fn_util_getByteLength(val) > maxlength) { // length
																			// 체크.
						alertInvalidMessage($_input2, messages, maxlength
								+ "자를 넘을 수 없습니다.", invalidCallbacks);
						isValid = false;
					}
				}); // input loop
	}); // form loop
	return isValid;
};
/* validation */

/*******************************************************************************
 * 기능 FUNCTION
 ******************************************************************************/
// 받아온 변수가 null, undefined, '' 일 경우 true 를 리턴.
var fn_comm_isNull = function(p_value) {
	if (p_value == '' || p_value == null || p_value == undefined) {
		return true;
	} else {
		return false;
	}
};

// 해당값이 null undefined 라면 '' 리턴
var fn_comm_rtnBlank = function(p_value) {

	if (p_value == null || p_value == 'null' || p_value == undefined
			|| p_value == 'undefined') {
		return '';
	} else {
		return p_value + '';
	}
};

/**
 * 입력 키 체크하여 입력 제한
 * 
 * @param obj :
 *            input박스 객체
 * @param type :
 *            num(정수), dnum(실수), eng(영문), engnum(영문+숫자)
 * @param decimalLength :
 *            실수 소수점자리수 fn_comm_keyCheck(document.getElementById('text'),
 *            'dnum', 3); //실수로서 3째자리까지만 입력 가능
 */
var fn_comm_keyCheck = function(obj, type, decimalLength) {
	return $(obj).fn_comm_keyCheck(type, decimalLength);
};

/**
 * $(".text").fn_comm_keyCheck('dnum', 3); //실수로서 3째자리까지만 입력 가능
 */
$.fn.fn_comm_keyCheck = function(type, decimalLength) {
	var $this = $(this);
	var rtn = undefined;
	$this.each(function(idx, obj) {
		var $obj = $(obj);
		if (type == undefined)
			type = 'num';
		var pattern = '';
		if (type == 'num')
			pattern = /[^0-9]/; // 숫자
		if (type == 'dnum')
			pattern = /[^0-9.]/; // 소수점 + 숫자
		if (type == 'eng')
			//pattern = /[ㄱ-힣]/; // 영문
		if (type == 'engnum')
			//pattern = /[ㄱ-힣][^0-9]/; // 영문 + 숫자

		var value = $obj.val();

		if (type == 'dnum') {
			if (value == '.')
				$obj.val('');
			var split = value.split('.');
			if (split.length > 2)
				$obj.val(value.substr(0, value.length - 1));
			if (split[1] != null && split[1].length > decimalLength)
				$obj.val(value.substr(0, value.length - 1));
		}
		if (pattern.test(value)) {
			if (type == 'num')
				$obj.val(value.replace(/[^0-9]/g, '')); // 숫자
			if (type == 'dnum')
				$obj.val(value.replace(/[^0-9.]/g, '')); // 소수점 + 숫자
			if (type == 'eng')
				//$obj.val(value.replace(/[ㄱ-힣]/g, '')); // 영문
			if (type == 'engnum')
				//$obj.val(value.replace(/[ㄱ-힣][^0-9]/g, '')); // 영문 + 숫자
			$obj.focus();
			rtn = false;
		}
	});
	return rtn;
};

/**
 * 
 * $(".text").fn_comm_attachKeyCheckEventHandler('dnum', 3);
 */
$.fn.fn_comm_attachKeyCheckEventHandler = function(type, decimalLength) {
	$(this).on("keyup", function(evt) {
		return $(this).fn_comm_keyCheck();
	});
};

/*******************************************************************************
 * Log 공통
 ******************************************************************************/
var logger = {
	log : function(msg) {
		try {
			console.log(msg);
		} catch (e) {
		}
	},

	ajaxResp : function(msg, data) {
		try {
			console.log(msg);
		} catch (e) {
		}
		try {
			console.dir(data);
		} catch (e) {
		}
	}
};

/*******************************************************************************
 * UI 처리관련 FUNCTION
 ******************************************************************************/
// 파라메터 가져오기
var fn_comm_getParameter = function() {

	var returnParam = new Object();

	var url = document.location.href;

	if (url.indexOf("?") > 0) {

		var paramUrl = decodeURIComponent(url.substring(url.indexOf("?") + 1,
				url.length));

		var paramArr = paramUrl.split("&");

		$.each(paramArr, function(index, value) {

			var key = value.split("=")[0];
			// var keyValue = decodeURIComponent(value.split("=")[1]); // 흠..
			// 암호화?? ㅋㅋ
			var keyValue = value.split("=")[1];

			if ((key.indexOf("FC_") == 0) && ($("#" + key).length == 0)) {

				$($("form")[0]).append(
						"<input type='hidden' name='" + key + "' id='" + key
								+ "' value='" + keyValue + "' />");
			}

			returnParam[key] = keyValue;
		});
	}

	return returnParam;
};

// 검색조건 자동입력
var fn_comm_setSearchOpt = function(detailData) {

	logger.ajaxResp("detailData", detailData);

	var prefix = "";
	var count = -1;

	$
			.each(
					detailData,
					function(key, value) {

						logger
								.log("#"
										+ prefix
										+ key
										+ " = "
										+ $("#" + prefix + key).is(
												"input[type=radio]"));
						if ($("#" + prefix + key).length > 0) {

							if ($("input[name*=" + key + "]").is(
									"input[type=checkbox]") == true
									|| $("input[name*=" + key + "]").is(
											"input[type=radio]") == true) {

								if ($("input[name*=" + key + "]").is(
										"input[type=checkbox]") == true) {
									logger.log("checkebox - 처리방안 필요함...  ㅋㅋ");
									$("#" + prefix + key).attr("checked", true);
								} else if ($("input[name*=" + key + "]").is(
										"input[type=radio]") == true) {

									$("#" + prefix + key + value).attr(
											"checked", true);

								}
							} else {
								if ($("#" + prefix + key).is("input") == true) {

									$("#" + prefix + key).val(value);

								} else if ($("#" + prefix + key).is("select") == true) {

									$("#" + prefix + key).val(value);
								} else if ($("#" + prefix + key).is("textarea") == true) {

									$("#" + prefix + key).val(value);
								}
							}

							count++;
						}
					});

	return count;
};

// 목록으로 이동
var fn_comm_goBackList = function(url) {

	var searchOpt = new Object();
	var searchOptObj = $('input[name^="FC_"]');

	$.each(searchOptObj, function(idx, obj) {

		var id = $(obj).attr('id');
		var value = $(obj).val();

		searchOpt[id] = value;
	});

	var pageInfo = {
		"url" : url,
		"param" : searchOpt

	};

	fn_comm_movePage(pageInfo);
};

// 페이지 이동
var fn_comm_movePage = function(pageInfo) {

	var url = pageInfo["url"];

	if ($.trim(url).length == 0) {
		alert("url을 확인하세요");
		return;
	}

	var param = pageInfo["param"] == undefined ? new Object()
			: pageInfo["param"];
	var strParam = "";

	$.each(param, function(key, value) {
		strParam += "&" + key + "=" + fn_comm_rtnBlank(value);
	});

	var searchOpt = pageInfo["searchOpt"] == undefined ? ""
			: pageInfo["searchOpt"];

	if ((typeof searchOpt) == "string") {

		if ($.trim(searchOpt).length > 0) {
			strParam += "&" + searchOpt;
		}
	} else {
		$.each(searchOpt, function(key, value) {
			strParam += "&" + key + "=" + fn_comm_rtnBlank(value);
		});
	}

	// url = url.indexOf("?") > 0 ? url + encodeURIComponent(strParam) : url +
	// "?" + encodeURIComponent(strParam.substring(1, strParam.length));
	url = url.indexOf("?") > 0 ? url + strParam : url + "?"
			+ strParam.substring(1, strParam.length);

	document.location.href = url;

};

/*----------------------------------------------------------------
 /기능 : 날짜를 요일로 반환한다.
 /인수 : day : 일자 (yyyyMMdd)   opt: 1-한자(月) 2-한글(월) 3-한글(월요일) 4-코드(e)
 /리턴 : 요일반환
 ----------------------------------------------------------------*/
var fn_comm_getDayToWeek = function(p_day, p_opt) {
	var v_week;

	v_week = fn_comm_dateToDayofWeek(p_day);

	if (p_opt == 1) {
		switch (v_week) {
		case 0:
			return "日";
			break;
		case 1:
			return "月";
			break;
		case 2:
			return "火";
			break;
		case 3:
			return "水";
			break;
		case 4:
			return "木";
			break;
		case 5:
			return "金";
			break;
		case 6:
			return "土";
			break;
		}
	} else if (p_opt == 2) {
		switch (v_week) {
		case 0:
			return "일";
			break;
		case 1:
			return "월";
			break;
		case 2:
			return "화";
			break;
		case 3:
			return "수";
			break;
		case 4:
			return "목";
			break;
		case 5:
			return "금";
			break;
		case 6:
			return "토";
			break;
		}
	} else if (p_opt == 3) {
		switch (v_week) {
		case 0:
			return "일요일";
			break;
		case 1:
			return "월요일";
			break;
		case 2:
			return "화요일";
			break;
		case 3:
			return "수요일";
			break;
		case 4:
			return "목요일";
			break;
		case 5:
			return "금요일";
			break;
		case 6:
			return "토요일";
			break;
		}
	} else if (p_opt == 4) {
		switch (v_week) {
		case 0:
			return "g";
			break;
		case 1:
			return "a";
			break;
		case 2:
			return "b";
			break;
		case 3:
			return "c";
			break;
		case 4:
			return "d";
			break;
		case 5:
			return "e";
			break;
		case 6:
			return "f";
			break;
		}
	}
};

/* ============================================================================ */
/*
 * 메소드 명 : fn_comm_dateToDayofWeek( p_date ) /* 내용 설명 : 날짜를 받아서 요일로 변환 /* 인자 :
 * yyyyMMdd /* RETURN 값 : int
 * /*============================================================================
 */
var fn_comm_dateToDayofWeek = function(p_date) {
	if (p_date.length < 0)
		return "";

	var v_year = p_date.substr(0, 4);
	var v_month = p_date.substr(4, 2);
	var v_day = p_date.substr(6, 2);

	var m = parseInt(v_month, 10) - 1;
	var d = parseInt(v_day, 10);

	var end = new Array(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
	if ((v_year % 4 == 0 && v_year % 100 != 0) || v_year % 400 == 0) {
		end[1] = 29;
	}

	if (d < 1 || d > end[m]) {
		return -1;
	}

	var newDate = new Date(v_year, m, v_day);

	return parseInt(String(newDate.getDay()));
};

/**
 * 페이징 생성을 위한 정보들의 전달 역할과 함께 페이징 관련 계산을 수행하는 클래스 형식의 함수입니다.
 * 
 */
var PaginationInfo = function() {

	/**
	 * Required Fields - 이 필드들은 페이징 계산을 위해 반드시 입력되어야 하는 필드 값들이다.
	 * 
	 * currentPageNo : 현재 페이지 번호 recordCountPerPage : 한 페이지당 게시되는 게시물 건 수
	 * pageSize : 페이지 리스트에 게시되는 페이지 건수, totalRecordCount : 전체 게시물 건 수.
	 */

	this.currentPageNo = 0;
	this.recordCountPerPage = 0;
	this.pageSize = 0;
	this.totalRecordCount = 0;

	this.getRecordCountPerPage = function() {
		return this.recordCountPerPage;
	};

	this.setRecordCountPerPage = function(recordCountPerPage) {
		this.recordCountPerPage = recordCountPerPage;
	};

	this.getPageSize = function() {
		return this.pageSize;
	};

	this.setPageSize = function(pageSize) {
		this.pageSize = pageSize;
	};

	this.getCurrentPageNo = function() {
		return this.currentPageNo;
	};

	this.setCurrentPageNo = function(currentPageNo) {
		this.currentPageNo = currentPageNo;
	};

	this.setTotalRecordCount = function(totalRecordCount) {
		this.totalRecordCount = totalRecordCount;
	};

	this.getTotalRecordCount = function() {
		return this.totalRecordCount;
	};

	/**
	 * Not Required Fields - 이 필드들은 Required Fields 값을 바탕으로 계산해서 정해지는 필드 값이다.
	 * 
	 * totalPageCount: 페이지 개수 firstPageNoOnPageList : 페이지 리스트의 첫 페이지 번호
	 * lastPageNoOnPageList : 페이지 리스트의 마지막 페이지 번호 firstRecordIndex : 페이징 SQL의
	 * 조건절에 사용되는 시작 rownum. lastRecordIndex : 페이징 SQL의 조건절에 사용되는 마지막 rownum.
	 */

	this.totalPageCount = 0;
	this.firstPageNoOnPageList = 0;
	this.lastPageNoOnPageList = 0;
	this.firstRecordIndex = 0;
	this.lastRecordIndex = 0;

	this.getTotalPageCount = function() {
		this.totalPageCount = Math.floor((this.getTotalRecordCount() - 1)
				/ this.getRecordCountPerPage()) + 1;
		return this.totalPageCount;
	};

	this.getFirstPageNo = function() {
		return 1;
	};

	this.getLastPageNo = function() {
		return this.getTotalPageCount();
	};

	this.getFirstPageNoOnPageList = function() {
		this.firstPageNoOnPageList = Math.floor((this.getCurrentPageNo() - 1)
				/ this.getPageSize())
				* this.getPageSize() + 1;
		return this.firstPageNoOnPageList;
	};

	this.getLastPageNoOnPageList = function() {
		this.lastPageNoOnPageList = this.getFirstPageNoOnPageList()
				+ this.getPageSize() - 1;
		if (this.lastPageNoOnPageList > this.getTotalPageCount()) {
			this.lastPageNoOnPageList = this.getTotalPageCount();
		}
		return this.lastPageNoOnPageList;
	};

	this.getFirstRecordIndex = function() {
		this.firstRecordIndex = (this.getCurrentPageNo() - 1)
				* this.getRecordCountPerPage();
		return this.firstRecordIndex;
	};

	this.getLastRecordIndex = function() {
		this.lastRecordIndex = this.getCurrentPageNo()
				* this.getRecordCountPerPage();
		return this.lastRecordIndex;
	};
};

/**
 * 페이징 컴포넌트 HTML 소스를 만드는 역할을 하는 클래스 형식의 함수입니다.
 * 
 */
var ImagePaginationRenderer = function(resourcesPath) {
	/*
	 * super.firstPageLabel = "<ul><a href=\"#\" onclick=\"{0}({1}); return
	 * false;\">[처음]</a>&#160;"; super.previousPageLabel = "<a href=\"#\"
	 * onclick=\"{0}({1}); return false;\">[이전]</a>&#160;";
	 * super.currentPageLabel = "<strong>{0}</strong>&#160;";
	 * super.otherPageLabel = "<a href=\"#\" onclick=\"{0}({1}); return
	 * false;\">{2}</a>&#160;"; super.nextPageLabel = "<a href=\"#\"
	 * onclick=\"{0}({1}); return false;\">[다음]</a>&#160;"; super.lastPageLabel = "<a
	 * href=\"#\" onclick=\"{0}({1}); return false;\">[마지막]</a>&#160;";
	 * 
	 * <ul> <li class="pre_end"><a href="javascript:;">맨 처음페이지로 가기</a></li>
	 * <li class="btn_pre"><a href="javascript:;">이전 페이지</a></li> <li><a
	 * href="javascript:;">1</a></li> <li><a href="javascript:;">2</a></li>
	 * <li><a href="javascript:;">3</a></li> <li class="on"><a
	 * href="javascript:;">4</a></li> <li><a href="javascript:;">5</a></li>
	 * <li><a href="javascript:;">6</a></li> <li><a href="javascript:;">7</a></li>
	 * <li><a href="javascript:;">8</a></li> <li><a href="javascript:;">9</a></li>
	 * <li><a href="javascript:;">10</a></li> <li class="btn_next"><a
	 * href="javascript:;">다음페이지로 가기</a></li> <li class="next_end"><a
	 * href="javascript:;">마지막 페이지로 가기</a></li> </ul>
	 */

	var firstPageLabel = "<a href='javascript:;' class='paging_first' onclick=\"{0}({1});\"><img src='"
			+ resourcesPath + "/images/board/paging_first.png' alt='맨앞' /></a>";
	var previousPageLabel = "<a href='#' class='paging_prev' onclick=\"{0}({1});\"><img src='"
			+ resourcesPath + "/images/board/paging_prev.png' alt='이전' /></a>";
	var currentPageLabel = "<a href=\'javascript:;\' class='on'>{0}</a>";
	var otherPageLabel = "<a href=\'javascript:;\' onclick=\"{0}({1});\">{2}</a>";
	var nextPageLabel = "<a href='javascript:;' class='paging_next' onclick=\"{0}({1});\"><img src='"
			+ resourcesPath + "/images/board/paging_next.png' alt='다음' /></a>";
	var lastPageLabel = "<a href='javascript:;' class='paging_last' onclick=\"{0}({1});\"><img src='"
			+ resourcesPath + "/images/board/paging_last.png' alt='맨뒤' /></a>";

	var MessageFormat = {
		format : function(str, replacements) {
			return str.replace(/\{(\d+)\}/g, function(match, p) {
				return replacements[p];
			});
		}
	};
	var StringBuffer = function() {
		this.result = "";
		this.append = function(str) {
			this.result += str;
			return this;
		};
		this.toString = function() {
			return this.result;
		};
	};

	var Integer = {
		parseInt : function(str) {
			return parseInt(str, 10);
		},
		toString : function(i) {
			return i + "";
		}
	};

	this.renderPagination = function(paginationInfo, jsFunction) {
		var strBuff = new StringBuffer();

		var firstPageNo = paginationInfo.getFirstPageNo();
		var firstPageNoOnPageList = paginationInfo.getFirstPageNoOnPageList();
		var totalPageCount = paginationInfo.getTotalPageCount();
		var pageSize = paginationInfo.getPageSize();
		var lastPageNoOnPageList = paginationInfo.getLastPageNoOnPageList();
		var currentPageNo = paginationInfo.getCurrentPageNo();
		var lastPageNo = paginationInfo.getLastPageNo();

		if (totalPageCount > pageSize) {
			if (firstPageNoOnPageList > pageSize) {
				strBuff.append(MessageFormat.format(firstPageLabel, [
						jsFunction, Integer.toString(firstPageNo) ]));
				strBuff.append(MessageFormat.format(previousPageLabel,
						[ jsFunction,
								Integer.toString(firstPageNoOnPageList - 1) ]));
			} else {
				strBuff.append(MessageFormat.format(firstPageLabel, [
						jsFunction, Integer.toString(firstPageNo) ]));
				strBuff.append(MessageFormat.format(previousPageLabel, [
						jsFunction, Integer.toString(firstPageNo) ]));
			}
		}
		strBuff.append("<span>");
		for (var i = firstPageNoOnPageList; i <= lastPageNoOnPageList; i++) {
			if (i == currentPageNo) {
				strBuff.append(MessageFormat.format(currentPageLabel, [ Integer
						.toString(i) ]));
			} else {
				strBuff
						.append(MessageFormat.format(otherPageLabel, [
								jsFunction, Integer.toString(i),
								Integer.toString(i) ]));
			}
		}
		strBuff.append("</span>");
		if (totalPageCount > pageSize) {
			if (lastPageNoOnPageList < totalPageCount) {
				strBuff.append(MessageFormat.format(nextPageLabel, [
						jsFunction,
						Integer.toString(firstPageNoOnPageList + pageSize) ]));
				strBuff.append(MessageFormat.format(lastPageLabel, [
						jsFunction, Integer.toString(lastPageNo) ]));
			} else {
				strBuff.append(MessageFormat.format(nextPageLabel, [
						jsFunction, Integer.toString(lastPageNo) ]));
				strBuff.append(MessageFormat.format(lastPageLabel, [
						jsFunction, Integer.toString(lastPageNo) ]));
			}
		}
		return strBuff.toString();
	};
};

/**
 * 데이터 배열을 받아 페이징 컴포넌트 구성 HTML 소스를 반환합니다.
 * 
 * pageSize 기본값은 10 입니다. paginationJsFunction 기본값은 linkPage 입니다.
 * 
 * @param data :
 *            기존 데이터 배열
 * @param currentPageNo :
 *            현재 페이지 번호
 * @param recordCountPerPage :
 *            페이지 하나에 표시할 최대 데이터 수
 * @param pageSize :
 *            화면에 표시할 페이지 링크 수
 * @param paginationJsFunction :
 *            페이지 링크 클릭 시 호출할 메소드 이름
 * @param totalCnt :
 *            전체 데이터 갯수, 명시하지 않으면 data 배열 원소 갯수로 지정됨
 * @returns 페이징 정보가 붙은 객체
 */
function fn_getPagingTag(data, currentPageNo, recordCountPerPage, pageSize,
		paginationJsFunction, totalCnt) {
	if (typeof (pageSize) == 'undefined' || pageSize == null) {
		pageSize = 10;
	}
	if (typeof (paginationJsFunction) == 'undefined'
			|| paginationJsFunction == null) {
		paginationJsFunction = 'linkPage';
	}
	var paginationInfo = new PaginationInfo();
	paginationInfo.setCurrentPageNo(Math.floor(Number(currentPageNo)));
	if (totalCnt)
		paginationInfo.setTotalRecordCount(totalCnt);
	else
		paginationInfo.setTotalRecordCount(data.length);
	paginationInfo
			.setRecordCountPerPage(Math.floor(Number(recordCountPerPage)));
	paginationInfo.setPageSize(Math.floor(Number(pageSize)));

	var paginationRenderer = new ImagePaginationRenderer(resourcesPath);
	return paginationRenderer.renderPagination(paginationInfo,
			paginationJsFunction);
}

/**
 * 데이터 배열을 페이징 정보가 붙은 객체로 만들어 반환합니다. fn_comm_setList 메소드에 사용이 가능합니다.
 * 
 * pageSize 기본값은 10 입니다. paginationJsFunction 기본값은 linkPage 입니다.
 * 
 * totalCnt 매개변수가 명시된 경우, data 에 페이지 내 데이터만 들어왔다고 가정함 --> 데이터 필터링 없음, 행 번호 자체 계산
 * totalCnt 매개변수가 명시되지 않은 경우, data 에 전체 데이터가 모두 들어왔다고 가정함 --> 데이터 필터링 있음
 * 
 * @param data :
 *            기존 데이터 배열
 * @param currentPageNo :
 *            현재 페이지 번호
 * @param recordCountPerPage :
 *            페이지 하나에 표시할 최대 데이터 수
 * @param pageSize :
 *            화면에 표시할 페이지 링크 수
 * @param paginationJsFunction :
 *            페이지 링크 클릭 시 호출할 메소드 이름
 * @param totalCnt :
 *            데이터 총 갯수 (입력하지 않는 경우 data 배열 원소 갯수로 지정됨)
 * @returns 페이징 정보가 붙은 객체
 */
function fn_attachPaging(data, currentPageNo, recordCountPerPage, pageSize,
		paginationJsFunction, totalCnt) {
	if (typeof (pageSize) == 'undefined' || pageSize == null)
		pageSize = 10;
	if (typeof (paginationJsFunction) == 'undefined'
			|| paginationJsFunction == null) {
		paginationJsFunction = 'linkPage';
	}

	var curPageNo = Math.floor(Number(currentPageNo));
	var recCountPerPage = Math.floor(Number(recordCountPerPage));
	var pgSize = Math.floor(Number(pageSize));

	var result = {};
	var pagedData = [];

	var rnum = 0; // 순방향 행번호
	var dnum = data.length + 1; // 역방향 행번호
	var cnt = data.length; // 총 갯수

	if (totalCnt) { // 총 갯수가 명시된 경우, data에 페이징된 데이터만 들어온 경우이므로, 데이터를 필터링하지 않는 대신
					// 행 번호를 계산해 주어야 함
		cnt = Number(totalCnt);
		rnum = (curPageNo - 1) * recCountPerPage;
		dnum = cnt;
		for (var idx = 0; idx < data.length; idx++) {
			rnum = idx + 1;
			dnum--;
			var row = data[idx];
			row["__CNT__"] = cnt;
			row["__RNUM__"] = dnum;
			row["__RNUM1__"] = rnum;
			pagedData.push(row);
		}
		result.list = pagedData;
		result.pagination = fn_getPagingTag(data, curPageNo, recCountPerPage,
				pgSize, paginationJsFunction, cnt);
	} else { // 총 갯수가 명시되지 않은 경우, data에 페이징 되지 않은 전체 데이터가 들어온 경우이므로 행 번호는 그냥
				// 매기면 되지만 데이터를 필터링해야 함
		for (var idx = 0; idx < data.length; idx++) {
			rnum = idx + 1;
			dnum--;
			var row = data[idx];
			row["__CNT__"] = cnt;
			row["__RNUM__"] = dnum;
			row["__RNUM1__"] = rnum;
			if (idx >= (curPageNo - 1) * recCountPerPage
					&& idx < curPageNo * recCountPerPage) {
				pagedData.push(row);
			}
		}
		result.list = pagedData;
		result.pagination = fn_getPagingTag(data, curPageNo, recCountPerPage,
				pgSize, paginationJsFunction);
	}

	return result;
}

/**
 * 해당 선택자에 페이징 컴포넌트를 배치합니다.
 * 
 * 예 : $('#paging').paging(2, data.length, 20, 10, 'linkPage');
 * 
 * pageSize 기본값은 10 입니다. paginationJsFunction 기본값은 linkPage 입니다.
 */
$.fn.paging = function(currentPageNo, totalRecordCount, recordCountPerPage,
		pageSize, paginationJsFunction) {
	if (typeof (pageSize) == 'undefined' || pageSize == null)
		pageSize = 10;
	if (typeof (paginationJsFunction) == 'undefined'
			|| paginationJsFunction == null) {
		paginationJsFunction = 'linkPage';
	}
	var paginationInfo = new PaginationInfo();
	paginationInfo.setCurrentPageNo(currentPageNo);
	paginationInfo.setTotalRecordCount(totalRecordCount);
	paginationInfo.setRecordCountPerPage(recordCountPerPage);
	paginationInfo.setPageSize(pageSize);

	var paginationRenderer = new ImagePaginationRenderer();
	var result = paginationRenderer.renderPagination(paginationInfo,
			paginationJsFunction);
	return this.each(function() {
		this.html(result);
	});
};

function __changeHeaderCheckbox__() {
	var $_headerCheckbox = $(this);
	var $_table = $_headerCheckbox.parentsUntil("table", ":last").parent();
	var columnIdx = $_headerCheckbox.data("__columnIdx__");
	$_table
			.find(
					"tr:not(:eq(0)) :nth-child(" + (columnIdx + 1)
							+ ") :checkbox").prop("checked",
					$_headerCheckbox.prop("checked"));
}

/**
 * 테이블의 헤더에 체크박스 전체선택 이벤트 추가
 */
$.fn.bindHeaderCheckboxEvent = function(columnIdx) {
	return this.each(function() {
		var $_this = $(this);
		if ($_this[0].tagName != "TABLE") {
			return;
		}

		var $_headerCheckbox = $_this.find("tr:eq(0) :eq(" + columnIdx
				+ ") :checkbox");
		$_headerCheckbox.data("__columnIdx__", columnIdx);
		$_headerCheckbox.off("change", __changeHeaderCheckbox__).on("change",
				__changeHeaderCheckbox__);
		var $_bodyCheckbox = $_this.find("tr:not(:eq(0)) :nth-child("
				+ (columnIdx + 1) + ") :checkbox");
		$_bodyCheckbox.on("change", function() {
			if ($(this).prop("checked")) {
				$_headerCheckbox.prop("checked", $_bodyCheckbox
						.filter(":checked").length == $_bodyCheckbox.length);
			} else {
				$_headerCheckbox.prop("checked", false);
			}
		});
	});
};

$.fn.fn_comm_scrollFocus = function(nDuration, nMargin) {
	nDuration = nDuration | 400;
	nMargin = nMargin | 0;
	var $_this = $(this);
	var pt = $_this.position().top;
	$('html, body').animate({
		scrollTop : pt - nMargin
	}, {
		duration : nDuration,
		complete : function() {
			$_this.focus();
		}
	});
};

function paginationRend(data, paginationId) {
	var pagination = fn_comm_processScalarAjax({
		url : contextPath + "/CM_CM03_CON/CM_CM03_R01.do",
		data : {
			currentPageNo : data.currentPageNo,
			totalRecordCount : data.totalRecordCount,
			recordCountPerPage : data.recordCountPerPage,
			templateCd : templateCd,
			templatePath : templatePath,
			paginationJsFunction : data.jsFunction,
			styleName : data.styleName
		}
	});
	$(paginationId).html(pagination);
}

/**
 * 태그를 없앰. 20171008 by hdy
 * 
 * @param str
 * @returns
 */
function stripTags(str) {
	if (str)
		return str.replace(/(<([^>]+)>)/gi, "");
}

function BBSList(MENU_SN) {
	var link = "";
	link = "/ko/cms/CM_BB01_CON/CM_BB01_L01.do?MENU_SN=" + MENU_SN;
	location.href = link;
}

/**
 * MENU_SN 과 BBS_SN 으로 해당 뷰 페이지로 이동
 */
function BBSView(MENU_SN, BBS_SN) {

	var link = "";
	switch (MENU_SN) {
	case 1884: // 사진일기
		// 해당 게시물이 몇페이지에 있는지 알아야 함.
		// 뷰 페이지로 이동 후 뷰 페이지 내 에서 몇 페이지인지 알아낸 후 linkPage(페이지번호) 을 수행 후 화면에 해당
		// 게시물을 표시하는 처리가 필요함.
		link = "/ko/cms/CM_BB01_CON/CM_BB01_L01.do?MENU_SN=" + MENU_SN
				+ "&BBS_SN=" + BBS_SN + "&ATCH_SN=1";
		break;
	case 1885: // 동영상갤러리
	case 1886: // 인터뷰,칼럼
	case 1889: // 공지사항
	case 1888: // 보도자료
	case 1887: // 정책자료
	case 1894: // 토론의장
	case 1891: // 모범사례
	case 1890: // 가장 많은 질문
		link = "/ko/cms/CM_BB01_CON/CM_BB01_V01.do?MENU_SN=" + MENU_SN
				+ "&BBS_SN=" + BBS_SN;
		break;
	}
	location.href = link;
}

/**
 * 해시태그를 이용해서 파라미터를 받고자 할 때 사용
 */
function hashParams(cb) {
	var hashArr = location.hash.substring(1).split("&");
	var hashParams = new Array;
	for ( var i in hashArr) {
		var tmp = hashArr[i].split("=");
		var key = tmp[0];
		var val = tmp[1]
		hashParams[key] = decodeURIComponent(val);
	}
	// 콜백처리
	if (typeof cb == 'function') {
		cb(hashParams);
	}
	return hashParams;
}

function hashProcess() {
	var hParams = hashParams();

	// 통합검색 처리
	if (typeof hParams != 'undefined' && typeof hParams.keyword != 'undefined'
			&& hParams.keyword != '') {
		document.frm_search.keyword.value = hParams.keyword;
		applySearch(hParams);
		applyMenu(hParams);
	}
}
function nl2br(str, is_xhtml) {
	var breakTag = (is_xhtml || typeof is_xhtml === 'undefined') ? '<br />'
			: '<br>';
	return (str + '').replace(/([^>\r\n]?)(\r\n|\n\r|\r|\n)/g, '$1' + breakTag
			+ '$2');
}

/**
 * 타임스탬프를 지정된 포멧으로 출력한다.
 * 
 * @param timestamp
 * @param format
 * @returns {String}
 */
function timestampFormat(timestamp, format) {
	var date = new Date(timestamp);

	var year = date.getFullYear();
	var month = date.getMonth() + 1;
	var day = date.getDate();
	var hour = date.getHours();
	var minute = date.getMinutes();
	var second = date.getSeconds();

	var result = "";

	if (typeof format == 'undefined') {
		format = "%Y-%M-%D: %H:%I:%S";
	}
	result = format.replace(/\%Y/gi, year).replace(/\%M/gi, zeroFill(month, 2))
			.replace(/\%D/gi, zeroFill(day, 2)).replace(/\%H/gi,
					zeroFill(hour, 2)).replace(/\%I/gi, zeroFill(minute, 2))
			.replace(/\%S/gi, zeroFill(second, 2));
	return result;
}

/**
 * 수(number) 를 지정된 숫자 (width) 만큼 0 으로 채움.
 * 
 * @param number
 * @param width
 * @returns
 */
function zeroFill(number, width) {
	width -= number.toString().length;
	if (width > 0) {
		return new Array(width + (/\./.test(number) ? 2 : 1)).join('0')
				+ number;
	}
	return number + ""; // always return a string
}

/**
 * 날짜 차이 계산해서 반환함.
 * 
 * @param diff_day
 * @param day
 * @returns {String}
 */
function date_diff(diff_day, day) {
	if (typeof day == 'undefined') {
		day = new Date();
	} else {
		day = new Date(day);
	}
	var d = (new Date(Date.parse(day) + diff_day * 1000 * 60 * 60 * 24));
	var ret = d.getFullYear() + '-' + zeroFill(d.getMonth() + 1, 2) + '-'
			+ zeroFill(d.getDate(), 2);
	return ret;
}

/*
 * Password Validator 0.1 비밀번호 검증 (c) 2007 Steven Levithan MIT License
 */

function validatePassword(pw, options) {
	// default options (allows any password)
	var o = {
		lower : 0,
		upper : 0,
		alpha : 0, /* lower + upper */
		numeric : 0,
		special : 0,
		length : [ 0, Infinity ],
		custom : [ /* regexes and/or functions */],
		badWords : [],
		badSequenceLength : 0,
		noQwertySequences : false,
		noSequential : false
	};

	for ( var property in options)
		o[property] = options[property];

	var re = {
		lower : /[a-z]/g,
		upper : /[A-Z]/g,
		alpha : /[A-Z]/gi,
		numeric : /[0-9]/g,
		special : /[\W_]/g
	}, rule, i;

	// enforce min/max length
	if (pw.length < o.length[0] || pw.length > o.length[1])
		return false;

	// enforce lower/upper/alpha/numeric/special rules
	for (rule in re) {
		if ((pw.match(re[rule]) || []).length < o[rule])
			return false;
	}

	// enforce word ban (case insensitive)
	for (i = 0; i < o.badWords.length; i++) {
		if (pw.toLowerCase().indexOf(o.badWords[i].toLowerCase()) > -1)
			return false;
	}

	// enforce the no sequential, identical characters rule
	if (o.noSequential && /([\S\s])\1/.test(pw))
		return false;

	// enforce alphanumeric/qwerty sequence ban rules
	if (o.badSequenceLength) {
		var lower = "abcdefghijklmnopqrstuvwxyz", upper = lower.toUpperCase(), numbers = "0123456789", qwerty = "qwertyuiopasdfghjklzxcvbnm", start = o.badSequenceLength - 1, seq = "_"
				+ pw.slice(0, start);
		for (i = start; i < pw.length; i++) {
			seq = seq.slice(1) + pw.charAt(i);
			if (lower.indexOf(seq) > -1 || upper.indexOf(seq) > -1
					|| numbers.indexOf(seq) > -1
					|| (o.noQwertySequences && qwerty.indexOf(seq) > -1)) {
				return false;
			}
		}
	}

	// enforce custom regex/function rules
	for (i = 0; i < o.custom.length; i++) {
		rule = o.custom[i];
		if (rule instanceof RegExp) {
			if (!rule.test(pw))
				return false;
		} else if (rule instanceof Function) {
			if (!rule(pw))
				return false;
		}
	}

	// great success!
	return true;
}

function checkPassword (str) {
	var password = str;
	var passed = validatePassword(password, {
	 length:   [9, Infinity],
	 lower:    1,
	 upper:    1,
	 numeric:  1,
	 special:  1,
	 badWords: ["password", "steven", "levithan"],
	 badSequenceLength: 4
	});
	console.log (passed);
	return passed;
}

function form_val_chk($frm) {
    var ok = true;
    $.each($frm.find('input, select, textarea'), function() {
        if ($(this).hasClass('req')) {
            switch ($(this).prop('tagName').toLowerCase()) {
            case 'select':
                if ($(this).find('option:selected').length < 1 || $(this).find('option:selected').val() == '') {
                    ok = false;
                    alert($(this).attr('title') ? $(this).attr('title') : '모든 항목을 선택해주세요.');
                    $(this).focus();
                    return false;
                }
                break;
            case 'textarea':
                if ($(this).val().replace(/ /g,'') == '') {
                    ok = false;
                    alert($(this).attr('title') ? $(this).attr('title') : '모든 항목을 입력해주세요.');
                    $(this).focus();
                    return false;
                }
                break;
            default:
                if ($(this).attr('type').toLowerCase() == 'radio' || $(this).attr('type').toLowerCase() == 'checkbox') {
                    if ($(this).attr('name').indexOf('[') > 0) obj_name_cond = 'input[name*="'+$(this).attr('name').substr(0, $(this).attr('name').indexOf('['))+'["]:checked';
                    else obj_name_cond = 'input[name="'+$(this).attr('name')+'"]:checked';
                    if ($frm.find(obj_name_cond).length < 1) {
                        ok = false;
                        alert($(this).attr('title') ? $(this).attr('title') : '모든 항목을 선택해주세요.');
                        return false;
                    }
                }
                else if ($(this).val().replace(/ /g,'') == '') {
                    ok = false;
                    alert($(this).attr('title') ? $(this).attr('title') : '모든 항목을 입력해주세요.');
                    if ($(this).attr('type').toLowerCase() != 'hidden') $(this).focus();
                    return false;
                }
                break;
            }
        }
        if ($(this).data('pattern') && $(this).val().replace(/ /g,'') != '') {
            if (!pattern_check($(this).data('pattern'), $(this).val())) {
                $(this).focus();
                ok = false;
                return false;
            }
        }
        if ($(this).data('minlen') && $(this).val().replace(/ /g,'') != '') {
            if ($(this).val().length < $(this).data('minlen')) {
                alert($(this).data('minlen')+'자 이상 입력해주세요.');
                $(this).focus();
                ok = false;
                return false;
            }
        }
    });
    if ($frm.find('.date_range').length > 0) {
        $.each($frm.find('.date_range'), function() {
            if ($(this).find('input.calendar:eq(0)').val() != '' && $(this).find('input.calendar:eq(1)').val() && $(this).find('input.calendar:eq(0)').val() > $(this).find('input.calendar:eq(1)').val()) {
                alert('시작일은 종료일보다 클 수 없습니다.');
                $(this).find('input.calendar:eq(0)').focus();
                ok = false;
                return false;
            }
        });
    }
    if (ok && $('input.agreeY').length > 0 && !$('input.agreeY').prop('checked')) {
        alert($('input.agreeY').attr('title')+'해주셔야 등록이 가능합니다.');
        ok = false;
    }
    return ok;
}

function getFileExtIcon(name){
	
	var ext = ".bmp .doc .gif .hwp .jpg .mp4 .pdf .png .ppt .swf .txt .xls .zip";
    var _fileLen = name.length;
    var _lastDot = name.lastIndexOf('.');
    var _fileExt = name.substring(_lastDot+1, _fileLen).toLowerCase();
    
    if(ext.indexOf(_fileExt) == -1) _fileExt = 'etc';
	
	return _fileExt;
}

$.fn.rowspan = function(colIdx, isStats) {
    return this.each(function(){        
        var that;       
        $('tr', this).each(function(row) {        
            $('td',this).eq(colIdx).filter(':visible').each(function(col) {  
                  
                if ($(this).html() == $(that).html() && (!isStats || isStats && $(this).prev().html() == $(that).prev().html() ) ) {              
                    rowspan = $(that).attr("rowspan") || 1;  
                    rowspan = Number(rowspan)+1;  
  
                    $(that).attr("rowspan",rowspan);  
                      
                    $(this).hide();  
                      
                } else {              
                    that = this;           
                }            
                  
                that = (that == null) ? this : that;        
            });
        });
    });
};

$.fn.rowspan2 = function(colIdx, isStats) {
    return this.each(function(){        
        var that;       
        $('tr', this).each(function(row) {        
            $('td,th',this).eq(colIdx).filter(':visible').each(function(col) {  
                  
                if ($(this).html() == $(that).html() && (!isStats || isStats && $(this).prev().html() == $(that).prev().html() ) ) {              
                    rowspan = $(that).attr("rowspan") || 1;  
                    rowspan = Number(rowspan)+1;  
  
                    $(that).attr("rowspan",rowspan);  
                      
                    $(this).hide();  
                      
                } else {              
                    that = this;           
                }            
                  
                that = (that == null) ? this : that;        
            });
        });
    });
};

function ifrSiteMapPop(id, src){
	$("#iframeSitePop").addClass("on");
	$spot = $("body").eq(0);
	$("html").css("overflow","hidden");
	$("body").css("overflow-y","scroll");
	$('<iframe id="iframe'+id+'" name="iframe'+id+'" src="'+src+'" frameborder="0" title="팝업프레임" class="on"/>').appendTo($spot);
	$('#iframe'+id).on('load',function(){
		$(this).show();
		$('#iframe'+id).contents().find('.sitemapArea').find('a').first().focus();/*190730 수정*/
    });
}

function ifrTotalSearchPop(id, src){
	$("#iframeSearchPop").addClass("on");
	$spot = $("body").eq(0);
	$("html").css("overflow","hidden");
	$("body").css("overflow-y","scroll");
	$('<iframe id="iframe'+id+'" name="iframe'+id+'" src="'+src+'" frameborder="0" title="팝업프레임" class="on"/>').appendTo($spot);
	$('#iframe'+id).on('load',function(){
		$(this).show();
		$(eval('document.iframe'+id+'.document')).find('.popClose').attr("tabindex","1");
		$(eval('document.iframe'+id+'.document')).find('article').attr("tabindex","2");
		$('#iframe'+id).contents().find('input').first().focus();
    });
}

function ifrPop(id, src, spot,scYn){
	$("#pop_dim").css("z-index","5000").addClass("on");
	$spot = $("body #container");
	if(typeof spot != "undefined") $spot = $(spot);
	if(!scYn || scYn != 'Y') $("body").css("overflow-y","hidden");
    if(scYn == 'Y'){
    	$('<iframe id="iframe'+id+'" name="iframe'+id+'" src="'+src+'" frameborder="0" class="pop_iframe on" title="팝업프레임" style="display: none; left: 0;border: 0px currentColor; border-image: none; top: 0px; width: 100%; height: '+$(top.document).height()+'px; position: absolute; z-index: 999999;"/>').appendTo($spot);
    	//$(eval('iframe'+id+'.document')).find('article').css('top',$(top.document).scrollTop()+100);
    	$('#iframe'+id).on('load',function(){
    		$(this).show();
    		var chk = $(eval('document.iframe'+id+'.document')).find('article').height()/2;
    		$(top.document).scrollTop(($(top.document).height()/2)-chk);
    		$(eval('document.iframe'+id+'.document')).find('.popClose').attr("tabindex","1");
    		$(eval('document.iframe'+id+'.document')).find('article').attr("tabindex","2");
    		$('#iframe'+id).focus();
        });
    }else{
    	$('<iframe id="iframe'+id+'" name="iframe'+id+'" src="'+src+'" frameborder="0" class="pop_iframe on" title="팝업프레임" style="display: none; left: 0;border: 0px currentColor; border-image: none; top: 0px; width: 100%; height: 100%; position: absolute; z-index: 999999;"/>').appendTo($spot);
    	$('#iframe'+id).on('load',function(){
    		//$(top.document).scrollTop(0);
    		$(this).show();
    		$(eval('document.iframe'+id+'.document')).find('.popClose').attr("tabindex","1");
    		$(eval('document.iframe'+id+'.document')).find('article').attr("tabindex","2");
    		$('#iframe'+id).focus();
        	/*var h = $(top.document).height() - $(top.document).scrollTop();
        	var chk = $(eval('iframe'+id+'.document')).find('article').height();
        	var chkH = h - chk;
        	if(chkH < 0){
        		$(eval('iframe'+id+'.document')).find('article').css('top',$(top.document).scrollTop()+chkH);
        	}else{
        		var c = ($(window).height() - chk)  > 0 ? ($(window).height() - chk)/2 : 0;
        		$(eval('iframe'+id+'.document')).find('article').css('top',$(top.document).scrollTop()+c);
        	}*/
        });
    }
    //$('<iframe id="iframe'+id+'" src="'+src+'" frameborder="0"  style="left: 0;border: 0px currentColor; border-image: none; top: '+($(document).scrollTop())+'px; width: 100%; height: 100%; position: absolute; z-index: 999999;"/>').appendTo($spot);
}

function ifrPopClose(id){
	$("body").css("overflow-y","");
	$("#pop_dim").removeClass("on");
	$("#iframe"+id).remove();
}

function graduateLogout(){
	location.href = "/graduate/FR_GAPPLY_CON/logout.do";
}
$(function(){
	//table caption(iOS 테이블 오류)
	$("table").each(function(){
		var obj = $(this).find("caption");
		$(obj).html("<p>"+$(obj).text()+"</p>");
		$("caption").removeAttr('class');
	});
	
	$("form").each(function(){
		$(this).find("textarea").each(function(){
			if($(this).attr("title")=="" || $(this).attr("title")===undefined)
			{
				$(this).attr("title","내용 입력창");
			}
		});
	});
});