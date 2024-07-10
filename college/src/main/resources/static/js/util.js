/**
 * util.js
 * 유틸성 공통 javascript.
 * 다른 javascript와 의존성이 없어야 한다.
 */


/**
 * 에러 메시지 처리 후 포커스를 넘김
 * Parameter : object, message
 */
function fn_util_errMsg(obj, msg)
{
    alert(msg);
    obj.select();
    obj.focus();
}

function fn_util_errMsg01(obj,msg){
    alert(msg);
    if(obj == "") return;
    obj.focus();
}

/**
 * 입력값이 NULL인지 체크
 * Parameter : value
 * Return : true / false
 */
function fn_util_isNull(objValue)
{
    if(objValue == null || objValue == "")
        return true;

    return false;
}

/**
 * 입력값에 스페이스 이외의 의미있는 값이 있는지 체크
 * Parameter : value
 * Return : true / false
 */
function fn_util_isEmpty(objValue)
{
    if(objValue == null || objValue.replace(/ /gi,"") == "")
        return true;

    return false;
}

/**
 * 입력값에 의미있는 값이 있는지 체크 (검사 대상에 그 어떤 객체도 올 수 있음)
 * null 이면 true
 * undefined 이면 브라우저 콘솔에 경고문구 출력 (개발자 도구에만 보임) 후 true (IE에서도 오류는 나지 않음), 이 문구가 보일 경우 화면 수정 권장함
 * 문자열이면, 띄어쓰기 등 공백을 모두 제거한 결과가 빈 문자열과 같으면 true
 * 배열이면, 길이가 0이면 true
 * JSON 형식 객체이면, 빈 객체인 경우 true (빈 객체 검사 로직은 jQuery 에서 제공)
 * 
 * 그 외에는 모두 false
 * 
 * Parameter : value (객체)
 * Return : true / false
 */
function fn_util_chkEmpty(objValue)
{
    if(typeof(objValue) == 'undefined') {
        try {console.log('주의 : ' + objValue + ' 가 undefined 합니다. 데이터를 잘못 꺼내지 않았는지 확인해 주세요.');} catch(e) {}
        return true;
    }
    if(objValue == null)
        return true;
    if((typeof(objValue)).toLowerCase() == 'string')
        return fn_util_isEmpty(objValue);
    if($.isArray(objValue) && objValue.length == 0)
        return true;
    if($.isPlainObject(objValue))
        return $.isEmptyObject(objValue);

    return false;
}


function fn_util_nvl(objValue, defValue)
{
    if (fn_util_isNull(objValue)) {
        if (defValue==undefined) {
            return "";
        }
        return defValue;
    }
    return objValue;
}

/**
 * 입력값의 한글여부 체크
 * Parameter : value
 * Return : true / false
 */
function fn_util_isKorean(objValue)
{
    var ch = "\0";
    var flag = true;

    for (var i = 0, ch = objValue.charAt(i); (i<objValue.length) && (flag); ch = objValue.charAt(++i))
    {
        if      ((ch >= '0') && (ch <= '9')) flag = false;
        else if ((ch >= 'a') && (ch <= 'z')) flag = false;
        else if ((ch >= 'A') && (ch <= 'Z')) flag = false;
        else if ( ch == ' ' || ch == '~' || ch == '`' || ch == '\\'||
                  ch == '-' || ch == '_' || ch == '|' || ch == '+' ||
                  ch == '=' || ch == ',' || ch == '.' || ch == '/' ||
                  ch == '<' || ch == '>' || ch == '?' || ch == '!' ||
                  ch == '@' || ch == '#' || ch == '$' || ch == '%' ||
                  ch == '^' || ch == '&' || ch == '*' || ch == '(' ||
                  ch == ')' || ch == '\"' || ch == '[' || ch == '(' )
                  flag = false;
    }

    return flag;
}

/**
 * 주민등록번호 체크
 * Parameter : value
 * Return : true / false
 */
function fn_util_isValidSSN(objValue)
{
    var year   = objValue.substring(0,2);
    var month  = objValue.substring(2,4);
    var day    = objValue.substring(4,6);
    var sex    = objValue.substring(6,7);
    var result = false;

    if     (sex=="1" || sex=="2")
        year="19"+year;
    else if(sex=="3" || sex=="4")
        year="20"+year;

    if(fn_util_isValidMonth(month) && fn_util_isValidDay(year, month, day))
    {
        var check   = 0;
        var frontNo = objValue.substring(0, 6);
        var rearNo  = objValue.substring(6,13);

        for(var i=0; i<= 5; i++)
            check = check + (( i % 8 + 2 )* parseInt(frontNo.substring(i,i+1)));

        for(var i=6; i<=11; i++)
            check = check + (( i % 8 + 2 )* parseInt(rearNo.substring(i-6,i-5)));

        check = 11 - (check % 11);
        check = check % 10;

        if(check == parseInt(objValue.substring(12,13)))
            result=true;
    }

    return result;
}

/**
 * 입력값이 특정 문자(chars)만으로 되어있는지 체크 (String값을 체크한다.)
 * 특정 문자만 허용하려 할 때 사용
 * ex) if (!fn_util_containsCharsOnly(form.blood.value ,"ABO"))
 *     {
 *         alert("혈액형 필드에는 A,B,O 문자만 사용할 수 있습니다.");
 *     }
 * Parameter : value, chars
 * Return : true / false
 */
function fn_util_containsCharsOnly(objValue, chars)
{
    for (var inx=0; inx<objValue.length; inx++)
    {
       if (chars.indexOf(objValue.charAt(inx)) == -1)
       return false;
    }
    return true;
}

/**
 * 입력값에 특정 문자(chars)가 들어있는지 체크 (String값을 체크한다.)
 * 특정 문자만 거부하려 할 때 사용
 * ex) if (fn_util_containsChars(form.blood.value ,"'%_"))
 *     {
 *         alert("검색 필드에는 ', %, _ 문자를 사용할 수 없습니다.");
 *     }
 * Parameter : value, chars
 * Return : true  - ', %, _ 문자가 들어 있는 경우
 *          false - ', %, _ 문자가 없는 경우
 */
function fn_util_containsChars(objValue, chars)
{
    for (var inx=0; inx<objValue.length; inx++)
    {
       if (chars.indexOf(objValue.charAt(inx)) != -1)
           return true;
    }
    return false;
}

/**
 *  문자열에서 Comma(,) 삭제
 *
 */
function fn_util_trimComma(inString)
{
    var len = inString.length;
    var ch, outString = "c";

    for (var i=1; i<=len; i++ )
    {
        ch = inString.substr(i-1, 1);
        if (ch == ",")
        {
        }
        else
        {
            outString = outString + ch;
        }
    }
    outlen = outString.length;
    outString = outString.substring(1,outlen);
    return outString;
}

/**
 *  문자열에서 Dot(.) 삭제
 *
 */
function fn_util_trimDot(inString)
{
    var len = inString.length;
    var ch, outString = "c";

    for (var i=1; i<=len; i++ )
    {
        ch = inString.substr(i-1, 1);
        if (ch == ".")
        {
        }
        else
        {
            outString = outString + ch;
        }
    }
    outlen = outString.length;
    outString = outString.substring(1,outlen);
    return outString;
}

/**
 *    '0'문자제거 (0001000 ==> 1000)
 * '수점 버거수정(2006.04.14)
 */
function fn_util_trimZero(argSt)
{
    var len = argSt.length;
    var out = "";
    if(len <= 0) return out;
    for(var i=0; i <= len; i++)
    {
        var ch = argSt.substr(i-1, 1);
        if (ch > 0 || ch == "-" || ch=='.') break;
    }
    out = argSt.substring(i-1);
    return out;
}

/**
 *    100,000 식의 쉼표 단위 붙이기
 *
 */
function fn_util_makeComma(num)
{
    var minus = undefined;
    if (num < 0) { num *= -1; minus = true;}
    else minus = false;

    var dotPos = (num+"").split(".");
    var dotU = dotPos[0];
    var dotD = dotPos[1];
    var commaFlag = dotU.length%3;

    var out = undefined;
    if(commaFlag) {
        out = dotU.substring(0, commaFlag);
        if (dotU.length > 3) out += ",";
    }
    else out = "";

    for (var i=commaFlag; i < dotU.length; i+=3) {
        out += dotU.substring(i, i+3);
        if( i < dotU.length-3) out += ",";
    }

    if(minus) out = "-" + out;
    if(dotD) return out + "." + dotD;
    else return out;
}

/**
 * 주어진 자리수만큼 소수점에서 절사(truncate)한다.
 *
 * 예:
 *    fn_util_trunc(3.25, 1)  :   3.25 ---> 3.2
 *    fn_util_trunc(-3.25, 1) :  -3.25 ---> -3.2
 */

function fn_util_pow(base, m) {
   var t = "";
   var k = Math.floor(m);
   if ((base == 0 && k > 0) || base == 1)
     return base;
   else if (base == 0 && k <= 0)
     return Number.NaN;
   else if (k == 0)
     return 1;
   else if (k == 1)
     return base;
   else if (k > 1) {
     var n = Math.floor(k);
     var n1 = Math.floor(n/2);
     var n2 = n - 2*n1;
     var y = fn_util_pow(base, n1);
     return y*y*fn_util_pow(base, n2);
   }
   else if (k < 0) {
     return 1.0/fn_util_pow(base, -k);
   }
}

function fn_util_trunc(x, count) {
  var m = fn_util_pow(10.0, count);
  var sign = (x < 0.0) ? -1.0 : 1.0;
  var y = (x < 0.0) ? -x : x;
  return sign*Math.floor(y*m)/m;
}

/**
 *    숫자인지 체크
 *    true - 음수, 0, 양수, 소수점이 있는 수
 *    false - 수가 아님
 */
function fn_util_isNumber(obj) {
    var str=obj.value;

    if (str == "") return false;

    if (isNaN(str) == true) {
        obj.value="";
        obj.focus();
        return false;
    }
    else {
        return true;
    }
}


/**
 *    숫자인지 체크
 *    true - 음수, 0, 양수, 소수점이 있는 수
 *    false - 수가 아님
 *
 *  input 에서 안 받고 변수에서 받아 처리할 수 있는 함수
 */
function fn_util_isNumberVal(str) {
    if (str == "") return false;
    return !isNaN(str);
}

/**
 *    숫자인지 체크
 *  true - 숫자
 *    false - 숫자가 아님
 */
function fn_util_isNum(objValue)
{
    var str="0123456789";
    if (objValue=="")
    {
        return false;
    }
    for (var i=0;i<objValue.length;i++)
    {
        if (str.indexOf(objValue.charAt(i))==-1)
        {
            return false;
        }
    }
    return true;
}


/**
 *    숫자인지 체크하고 숫자가 아니면 메시지 창을 띄움
 *  true - 숫자
 *    false - 숫자가 아님
 */
function fn_util_isPositiveNumber(obj)
{
    var str="0123456789";
    if (obj.value=="")
    {
        return false;
    }
    for (var i=0;i<obj.value.length;i++)
    {
        if (str.indexOf(obj.value.charAt(i))==-1)
        {
            obj.value="";
            obj.focus();
            return false;
         }
    }
    return true;
}

/**
 *    정수만 입력 받음(음수, 0, 양수).
 *  true - 정수
 *    false - 정수가 아님
 */
function fn_util_isInteger(obj)
{
    var str="-0123456789";
    if (obj.value=="")
    {
        return false;
    }
    for (var i=0;i<obj.value.length;i++)
    {
        if (str.indexOf(obj.value.charAt(i))==-1)
        {
            obj.value="";
            obj.focus();
            return false;
         }
    }
    if (isNaN(obj.value) == true) {
        obj.value="";
        obj.focus();
        return false;
    }
    return true;
}

/**
 *    공백문자 제거
 *
 */
function fn_util_trimString(inString)
{
    var outString;
    var startPos;
    var endPos;
    var ch;

    // where do we start?
    startPos = 0;
    ch = inString.charAt(startPos);
    while ((ch == " ") || (ch == "\b") || (ch == "\f") || (ch == "\n") || (ch == "\r") || (ch == "\n"))
    {
        startPos++;
        ch = inString.charAt(startPos);
    }

    // where do we end?
    endPos = inString.length - 1;
    ch = inString.charAt(endPos);
    while ((ch == " ") || (ch == "\b") || (ch == "\f") || (ch == "\n") || (ch == "\r") || (ch == "\n"))
    {
        endPos--;
        ch = inString.charAt(endPos);
    }

    // get the string
    outString = inString.substring(startPos, endPos + 1);

    return outString;
}

/**
* 입력값이 길이 구하기(byte로)
*/
function fn_util_getInputByteLength(input) {
    var byteLength = 0;
    for (var inx = 0; inx < input.value.length; inx++) {
    var oneChar = escape(input.value.charAt(inx));
    if ( oneChar.length == 1 ) {
        byteLength ++;
    } else if (oneChar.indexOf("%u") != -1) {
        byteLength += 2;
    } else if (oneChar.indexOf("%") != -1) {
        byteLength += oneChar.length/3;
    }
    }
    return byteLength;
}

function fn_util_getByteLength(s) {
    if (s==null || s==undefined)
        return 0;
    var b,i,c;
    for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
    return b;
}

function fn_util_getDate()
{
    var today = new Date();

    var toYYYY = today.getFullYear() ;
    var toMM   = today.getMonth() + 1 ;
     if(toMM >= 0 && toMM <= 9) toMM = "0" + toMM ;

    var toDD   = today.getDate() ;
     if(toDD >= 0 && toDD <= 9) toDD = "0" + toDD ;

    var toDate = toYYYY + "." + toMM + "." + toDD;

    return toDate;
}

/*
 * fn_util_changeChar(str, chr1, chr2) : str을 받아 chr1의 문자를 chr2로
 *                                  바꾸어준다.
 */
function fn_util_changeChar(str, chr1, chr2) {
  var src = new String(str);
  var tar = new String();
  var i, len=src.length;
  for (i=0; i < len; i++) {
    if (src.charAt(i) == chr1)
      tar += chr2;
    else
      tar += src.charAt(i);
  }
  return tar;
}

/*
 * fn_util_removeChar       :   문자열중에서 특정 문자만 제거한 값 return
 *          fn_util_removeChar("1","2")
 *          --> 1: 문자열(String)
 *              2: 제거할 문자
 */
function fn_util_removeChar(str, chr) {
    var src = new String(str);
    var tar = new String();
    var i, len=src.length;
    for (i=0; i < len; i++) {
        if (src.charAt(i) == chr)
            tar += '';
        else
            tar += src.charAt(i);
    }
    return tar;
}

/*   fn_util_tab_order        :   입력필드에 입력이 끝나면 자동으로 focus이동
 *                           (입력필드의 onkeyup event에 사용할것)
 *          fn_util_tab_order("1","2","3")
 *          --> 1: Input Box object
 *              2: focus를 이동시킬 object name
 *              3: focus 이동위해 1번 object에 입력되어야 할 자리수
 */
function fn_util_tab_order(arg,nextname,len) {
  if (arg.value.length == len) {
      nextname.focus() ;
      return;
  }
}

// 메일 체크

function fn_util_validEmail(arg_v) {

    var a = arg_v.lastIndexOf("@");
    var b = arg_v.lastIndexOf(".");
    var c = arg_v.indexOf(":");
    var d = arg_v.indexOf("/");
    var e = arg_v.substring(0,a);
    var f = e.indexOf("@");
    var g = arg_v.substring(a+1,arg_v.length);
    var h = g.indexOf("[");
    var i = g.indexOf("]");
    var j = g.indexOf("<");
    var k = g.indexOf(">");
    var l = arg_v.substring(a+1,b);
    var m = arg_v.substring(b+1,arg_v.length);
    var n = arg_v.substring(0,a);
    var o = 0;
    var p = arg_v.indexOf(";");
    var q = arg_v.indexOf(" ");
    if (a > b) {o++;}
    if (c != -1) {o++;}
    if (d != -1) {o++;}
    if (f != -1) {o++;}
    if (h != -1) {o++;}
    if (i != -1) {o++;}
    if (j != -1) {o++;}
    if (k != -1) {o++;}
    if (l.length < 2) {o++;}
    if (m.length < 2) {o++;}
    if (n.length < 1) {o++;}
    if (p != -1) {o++;}
    if (q != -1) {o++;}
    if (o == 0) {
        return true;
    }
    else {
        alert("메일 전송가능한 주소로 정확하게 기입해 주십시오.");
        return false;
    }
}

// 영문 판별
function fn_util_alphaCheck(arg_v)
{
    var alphaStr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if ( alphaStr.indexOf(arg_v) < 0 )
        return false;
    else
        return true;
}


function fn_util_isAlphaNum(input)
{
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return fn_util_containsCharsOnly(input.value,chars);
}

/*
 * 유효한 일(日)인지 확인.
 * Parameter : YYYY, MM, DD(년, 월, 일)
 * Return : true / false
 */
function fn_util_isValidDay(yyyy, mm, dd)
{
    var m = parseInt(mm,10) - 1;
    var d = parseInt(dd,10);

    var end = new Array(31,28,31,30,31,30,31,31,30,31,30,31);
    if ((yyyy % 4 == 0 && yyyy % 100 != 0) || yyyy % 400 == 0)
        end[1] = 29;

    return (d >= 1 && d <= end[m]);
}

/* 유효한 월(月)인지 확인.
 * Parameter : MM(월)
 * Return : true / false
 */
function fn_util_isValidMonth(mm)
{
    var m = parseInt(mm,10);

    return (m >= 1 && m <= 12);
}

/*
 * 유효한 날짜(Date) 인지 체크
 * Parameter : YYYYMMDD(년월일)
 * Return : true / false
 */
function fn_util_isValidDate(objValue)
{
    if(!fn_util_isNum(objValue) || objValue.length < 8)
        return false;

    var year  = objValue.substring(0, 4);
    var month = objValue.substring(4, 6);
    var day   = objValue.substring(6, 8);

    if (parseInt(year, 10) >= 1900  && fn_util_isValidMonth(month) && fn_util_isValidDay(year, month, day))
        return true;

    return false;
}

/*
 * 유효한 시간(Time) 인지 체크
 * Parameter : HHMMSS(시분초)
 * Return : true / false
 */
function fn_util_isValidTime(objValue)
{
    if(!fn_util_isNum(objValue))
        return false;

    var hour = objValue.substring(0, 2);
    var min  = objValue.substring(2, 4);
    var sec  = objValue.substring(4, 6);

    if(hour < 24 && min < 60 && sec < 60)
        return true;

    return false;
}

/*
 * 날짜 입력시 날짜의 dash('-')를 삭제하는 함수
 * 날짜 입력란의 onFocus()시 호출
 * Parameter : object
 */
function fn_util_delDateDelim(obj)
{
    obj.value = obj.value.replace(/-/gi,"");
}

/*
 * 날짜 입력시 날짜의 dash('-')를 추가하는 함수
 * 날짜 입력란의 onBlur()시 호출
 * Parameter : object
 */
function fn_util_addDateDelim(obj)
{
    obj.value = fn_util_addDateDelimeter(obj.value);
}

/*
 * 날짜(yyyymmdd)를 받아 dash('-')를 추가하는 함수
 *
 * return : yyyy-mm-dd
 */
function fn_util_addDateDelimeter(dateValue)
{
    var year  = dateValue.substring(0, 4);
    var month = dateValue.substring(4, 6);
    var day   = dateValue.substring(6, 8);

    return year + "-" + month + "-" + day;

}

/*
 * 시간 입력시 시간의 Colon(':')을 삭제하는 함수
 * 시간 입력란의 onFocus()시 호출
 * Parameter : object
 */
function fn_util_delTimeDelim(obj)
{
    obj.value = obj.value.replace(/:/gi,"");
}

/*
 * 시간 입력시 시간의 Colon(':')을 추가하는 함수
 * 시간 입력란의 onBlur()시 호출
 * Parameter : object
 */
function fn_util_addTimeDelim(obj)
{
    var varTime = obj.value;

    if ((varTime != null) && (varTime != ""))
    {
        var hour = varTime.substring(0, 2);
        var min  = varTime.substring(2, 4);
        var sec  = varTime.substring(4, 6);

        obj.value = hour + ":" + min + ":" + sec;
    }
}

/*
 * 현재 시간을 가져오는 함수
 * return Hour(시)
 */
function fn_util_getHour()
{
    var cDate = new Date();

    return cDate.getHours();
}

/*
 * 현재 분을 가져오는 함수
 * return Minute(분)
 */
function fn_util_getMinute()
{
    var cDate = new Date();

    return cDate.getMinutes();
}

/*
 * 현재 초를 가져오는 함수
 * return Second(초)
 */
function fn_util_getSecond()
{
    var cDate = new Date();

    return cDate.getSeconds();
}

function fn_util_isValidTermDate(fromDate, toDate) {
  return fn_util_parseDate(fromDate).getTime() < fn_util_parseDate(toDate).getTime();
}

function fn_util_makeDate(str, chr) {
    if(str==null || str.length<8) return '';

    if (chr==undefined || chr==null)
        chr = "-";
    str = fn_util_removeDate(str);
    var yyyy = str.substring(0, 4); // year
    var MM = str.substring(4, 6); // month
    var dd  = str.substring(6, 8); // day

    return yyyy + chr + MM + chr + dd;
}

function fn_util_makeTime(str, chr) {
    if(str==null || str.length<4) return '';

    if (chr==undefined || chr==null)
        chr = ":";
    str = fn_util_removeTime(str);
    var HH = str.substring(0, 2); // HH
    var mm = str.substring(2, 4); // mm
    if (str.length>5) {
        var ss = str.substring(4, 6); // ss
        return HH + chr + mm + chr + ss;
    } else {
        return HH + chr + mm;
    }
}

function fn_util_parseDate(str) {
    if (str==null || str==undefined)
        return null;
    str = fn_util_removeTime(fn_util_removeDate(str));
    str = fn_util_removeChar(str, ' ');
    var date = null;
    if (str.length<8) {
        return null;
    } else if (str.length>=8) {
        date = new Date(parseInt(str.substring(0,4)), parseInt(str.substring(4,6))-1, parseInt(str.substring(6,8)));
    }
    if (str.length>=10) {
        date.setHours(parseInt(str.substring(8,10)));
    }
    if (str.length>=12) {
        date.setMinutes(parseInt(str.substring(10,12)));
    }
    if (str.length>=14) {
        date.setSeconds(parseInt(str.substring(12,14)));
    }
    return date;
}

function fn_util_formatDate(dateObj, chr) {
    if (chr==undefined || chr==null)
        chr = "-";
    var yyyy = dateObj.getFullYear() ;
    var MM = dateObj.getMonth() + 1 ;
    if (MM >= 0 && MM <= 9) MM = "0" + MM ;

    var dd   = dateObj.getDate() ;
    if (dd >= 0 && dd <= 9) dd = "0" + dd ;

    var dateStr = yyyy + chr + MM + chr + dd;
    return dateStr;
}

function fn_util_formatTime(dateObj, chr) {
    if (chr==undefined || chr==null)
        chr = ":";
    var HH = dateObj.getHours() ;
    if (HH >= 0 && HH <= 9) HH = "0" + HH ;

    var mm = dateObj.getMinutes() ;
    if (mm >= 0 && mm <= 9) mm = "0" + mm ;

    var timeStr = HH + chr + mm;
    return timeStr;
}

/**
 * 윈도우의 중앙에 Popup창을 연다
 * Parameter :
 */
function fn_util_openWindow(url, width, height, scroll, windowName)
{
    windowName = fn_util_nvl(windowName);
    var winx = (screen.width - width ) / 2;
    var winy = (screen.height- height) / 2;
    var settings  =
        "height=    " + height + ", " +
        "width=     " + width  + ", " +
        "top=       " + winy   + ", " +
        "left=      " + winx   + ", " +
        "scrollbars=" + scroll + ", " +
        "resizable=no";

    var win = window.open(url, windowName, settings);

    return win;
}

/**
 * 윈도우의 중앙에 Modal Popup창을 연다
 * Parameter :
 */
function fn_util_openModal(url, arguments, width, height, scroll)
{
    var winx = (screen.width - width ) / 2;
    var winy = (screen.height- height) / 2;
    var settings  = "dialogHeight:    " +height+"px; ";
        settings += "dialogWidth:     " +width +"px; ";
        settings += "dialogTop:       " +winy  +"px; ";
        settings += "dialogLeft:      " +winx  +"px; ";
        settings += "scroll    :" +scroll+"; ";
        settings += "resizable :no; ";
        settings += "help      :no; ";
        settings += "status    :no; ";
        //settings += "unadorned:yes";

    var returnValue = showModalDialog(url, arguments, settings);

    return returnValue;
}

/**
 * 전체크기 브라우져를 연다
 * Parameter :
 */
function fn_util_openFullScreen(url)
{
    window.open(url, "", "fullScreen");
}

/**
 * 숫자를 한글로
 */
function fn_util_num2han(num){
    var i, j=0, k=0;
    var han1 = new Array("","일","이","삼","사","오","육","칠","팔","구");
    var han2 = new Array("","만","억","조","경","해","시","양","구","간");
    var han3 = new Array("","십","백","천");
    var result="", hangul = num + "", pm = "";
    var str = new Array(), str2="";
    var strTmp = new Array();

    if(parseInt(num)==0) return "영"; //입력된 숫자가 0일 경우 처리
    if(hangul.substring(0,1) == "-"){ //음수 처리
        pm = "마이너스 ";
        hangul = hangul.substring(1, hangul.length);
    }
    if(hangul.length > han2.length*4) return "too much number"; //범위를 넘는 숫자 처리 자리수 배열 han2에 자리수 단위만 추가하면 범위가 늘어남.

    for(i=hangul.length; i > 0; i=i-4){
        str[j] = hangul.substring(i-4,i); //4자리씩 끊는다.
        for(k=str[j].length;k>0;k--){
            strTmp[k] = (str[j].substring(k-1,k))?str[j].substring(k-1,k):"";
            strTmp[k] = han1[parseInt(strTmp[k])];
            if(strTmp[k]) strTmp[k] += han3[str[j].length-k];
            str2 = strTmp[k] + str2;
        }
        str[j] = str2;
        //if(str[j]) result = str[j]+han2[j]+result;
        //4자리마다 한칸씩 띄워서 보여주는 부분. 우선은 주석처리
        //result = (str[j])? " "+str[j]+han2[j]+result : " " + result;
        result = (str[j])? " "+str[j]+han2[j]+result : " " + result;

        j++; str2 = "";
    }

    return pm + result; //부호 + 숫자값
}


function fn_util_removeDateObj(obj) {
  obj.value = fn_util_removeDate(obj.value);
}

function fn_util_removeDate(str) {
  return fn_util_removeChar(fn_util_removeChar(str, '-'), '.');
}

function fn_util_removeTime(str) {
  return fn_util_removeChar(fn_util_removeChar(str, ':'), '.');
}

function fn_util_makeDateObj(obj) {
  if(fn_util_isDate(obj.value)==false) {
    alert('날짜 형식에 맞지 않습니다.');
    obj.focus();
    return;
  }

    obj.value = fn_util_makeDate(obj.value);
}

function fn_util_isDate(str) {

  var src = fn_util_removeDate(str);

  if(fn_util_isNumber2(src)==false) return false;
  if(src.length==0) return;
  if(src.length!=8) return false;

  var yea = src.substring(0, 4); // year
  var mon = src.substring(4, 6); // month
  var da  = src.substring(6, 8); // day

  //기본적인 일, 월, 년 에러 검색
  if(mon < 1 || mon > 12) return false;
  if(da  < 1 || da  > 31) return false;

  var d = new Date(yea, mon - 1, da);

  if(yea<'2000') yea = src.substring(2, 4);
  if(yea!=d.getYear() || mon!=(d.getMonth()+1) || da!=d.getDate())
    return false;
}

function fn_util_isNumber2(str) {
  var src = new String(str);
  var tar = true;
  var i, len=src.length;

  for (i=0; i < len; i++) {
    if((src.charAt(i) < '0') | (src.charAt(i) > '9'))
      if(i==0) {
      if(src.charAt(i) != '-')
        return false;
    } else {
      if(src.charAt(i) != '.')
        return false;
    }
  }
  return true;
}

//날짜 형식 체크
function fn_util_checkDate(inform) {
    var len        = inform.length;
    var k         = 0;
    var YunYear    = 0;

    if ( len != 10 ) {
        alert("날짜입력양식이 틀렸습니다.\n(예)2001/04/01");
        return false;
    } else {
        // '-'뺀 날짜로 생성
        inform = inform.substring(0,4) + inform.substring(5,7)
                    + inform.substring(8,10);
    }

    for (var i = 0 ; i < len ; i++ ) {
        if ( inform.charAt(i) >= "0" && inform.charAt(i) <= "9" )
        {
            k++;
        }
    }

    if ( k < 8 ) {
        alert( "날짜에는 문자나 특수문자를 사용하실수 없습니다.\n(예)20001201 ");
        return false;
    }

    var IYear    = inform.substring(0, 4);    // 년도
    var IMonth     = inform.substring(4, 6);     // 월
    var IDay    = inform.substring(6, 8);     // 일

    if ( IYear.substring(0, 4) <= 1945 || IYear.substring(0, 4) >= 2100 ) {
        alert( "1945년 이전과 2100년 이후는 입력하실수가 없습니다.");
        return false;
    }

    if ( IMonth < 1 || IMonth > 12 || IDay < 1 || IDay > 31 ) {
        alert("월 또는 일자를 잘못입력하셨습니다.");
        return false;
    }
    if ( IMonth == 4 || IMonth == 6 || IMonth == 9 || IMonth == 11 )
        if ( IDay == 31 ) {
            alert( "이달은 31일이 없습니다.");
            return false;
        }

    if ( parseInt(IYear/4)*4 == IYear ) {
        YunYear = 1;
        if ( parseInt(IYear/100)*100 == IYear ) {
            YunYear = 0;
            if ( parseInt(IYear/400)*400 == IYear ) {
                YunYear = 1;
            }
        }
    }

    if ( IMonth == 2 ) {
        if ( IDay > 29 ) {
            alert( "2월달은 29일을 넘을수 없습니다.");
            return false;
        }

        if ( YunYear == 0 )
            if ( IDay > 28 ) {
                alert("이해의 2월은 28일까지입니다.");
                return false;
            }
    }

    //alert("정상적인 날짜입니다.");
    return true;
}

function fn_util_checkDate_YYYY(argObj) //============년도체크
{
    if (argObj.value.length != 4) return false;

    if (!fn_util_isNumber(argObj)) return false;

    if ( argObj.value <= 1945 || argObj.value >= 2100 ) return false;

    return true;
}



function fn_util_checkDate_stat(value1, value2) {
    value1 = fn_util_removeDate(value1);
    value2 = fn_util_removeDate(value2);

    if( value1 > value2 ){
        alert("시작일이 종료일보다 큽니다.");
        return false;
    }
    return true;
}

function fn_util_checkBizNo(argObj01, argObj02, argObj03){  //사업자번호체크

    if(argObj01.val().length != 3) return false;
    if(argObj02.val().length != 2) return false;
    if(argObj03.val().length != 5) return false;

    var BizNo = argObj01.val() + argObj02.val() + argObj03.val();

    if( !fn_util_isNum(BizNo) ) return false;

    var comStr="13713713";
    var bizValue=0;

    for(var i=0; i < 8 ; i++){
        bizValue=bizValue + ( parseFloat(BizNo.substring(i,i+1)) * parseFloat(comStr.substring(i,i+1))) % 10;
    }

    var tempCom= parseFloat(BizNo.substring(8,9)) * 5 + "0";
    var checkValue=parseFloat(tempCom.substring(0,1)) +parseFloat(tempCom.substring(1,2));
    var checkDigit=( 10 - (bizValue + checkValue ) % 10 ) %10 ;

    if( BizNo.substring(9,10) != checkDigit) return false;

    return true;
}

function fn_util_chooseCheckBox(argObj)
{
    var tCount = argObj.length;
    var tTemp = "";

    if(tCount == null)
    {
        tTemp = argObj.value;
    } else {
        for(var i=0; i < tCount; i++)
        {
            if(argObj[i].checked == true)
            {
                tTemp = argObj[i].value;
                break;
            }
        }
    }

    return tTemp;
}

function fn_util_checkDecimalsForNum(theNum, thePointCnt)
{
    var NomalDecimals = true ;
    var sNum = theNum ;
    var sPointCnt = thePointCnt ;
    var arrNum = sNum.split(".") ;          // default '1' return
    var iPointerCnt = arrNum.length ;
    if (iPointerCnt < 2){
        NomalDecimals = true;
    }
    else if (iPointerCnt == 2){
        var sDecimal = arrNum[1];
        var iDecimalLen = sDecimal.length ;
        if (iDecimalLen <= sPointCnt)       // Normal
            NomalDecimals = true ;
        else
            NomalDecimals = false ;
    }
    else{
        NomalDecimals = false ;             // irregular
    }

    return NomalDecimals ;
}


function fn_util_htmlEncode(val, initV) {
    if (val==null || val==undefined)
        return initV;
    var str = new String(val);
    str =
        str.replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/<br\/>/g, "\n")
        .replace(/<br>/g, "\n")
        ;
    return str;
}

function fn_util_htmlDecode(val, initV) {
    if (val==null || val==undefined)
        return initV;
    var str = new String(val);
    str =
        str.replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&#34;/g, '"')
        ;
    return str;
}

function fn_util_parseJsonFromArray(arr, nameKey, valueKey) {
    var jsonResult = {};
    if (valueKey) {
        for (var idx=0; idx<arr.length; idx++) {
            var oneObj = arr[idx];
            jsonResult[oneObj[nameKey]] = oneObj[valueKey];
        }
    } else {
        for (var idx=0; idx<arr.length; idx++) {
            var oneObj = arr[idx];
            jsonResult[oneObj[nameKey]] = oneObj;
        }
    }
    return jsonResult;
}

/**
 * 문자열을 논리값(true/false)으로 변환합니다.
 */
function fn_util_parseBoolean(obj) {
    if(typeof(obj) == 'number') {
        if(obj == 0) return false;
        return true;
    }else if(typeof(obj) == 'boolean') {
        return obj;
    }else if(typeof(obj) == 'string') {
        if(obj == 'y') return true;
        else if(obj == 'Y') return true;
        else if(obj == 't') return true;
        else if(obj == 'T') return true;
        else if(obj == 'yes') return true;
        else if(obj == 'YES') return true;
        else if(obj == 'n') return false;
        else if(obj == 'N') return false;
        else if(obj == 'f') return false;
        else if(obj == 'F') return false;
        else if(obj == 'no') return false;
        else if(obj == 'NO') return false;
        else if(obj == 'true') return true;
        else if(obj == 'false') return false;
        else throw obj + " 를 논리값으로 변환할 수 없습니다.";
    }else throw obj + " 를 논리값으로 변환할 수 없습니다.";
}

/**
 * 사용자의 브라우저 타입을 판별해 냅니다.
 * 결과는 JSON 형식으로, 필드로 browserName, version 을 가집니다. 둘 다 문자열 타입입니다.
 * PC용 브라우저는 대부분 판별이 가능하며, 엔진을 빌려 쓰는 브라우저의 경우 엔진에 해당하는 원래의 브라우저에 대한 정보가 반환됩니다.
 * 
 * @returns 브라우저 정보 (browserName, version)
 */
function fn_util_getBrowserType() {
    var agent = navigator.userAgent;
    var lowerCased = String(agent).toLowerCase();
    var results = {browserName : '', version : ''};
    var works = [];
    var browserNameIndex = -1;
    var browserKeyword = '';
    var indexOfKeyword = '';

    if (lowerCased.indexOf('msie') >= 0 || lowerCased.indexOf('trident') >= 0) { // IE
        results.browserName = 'Internet Explorer';
        works.push({ browserKeyword: 'msie', indexOfKeyword: ';' });
        works.push({ browserKeyword: 'rv:', indexOfKeyword: ')' });
    }
    else if(lowerCased.indexOf('edge') >= 0) { // Microsoft Edge
        results.browserName = 'Edge';
        works.push({ browserKeyword: 'edge/', indexOfKeyword: null });
    }
    else if (lowerCased.indexOf('presto') >= 0) { // Opera (Presto)
        results.browserName = 'Opera (Presto based)';
        works.push({browserKeyword : 'opera/', indexOfKeyword : ' '});
    }
    else if (lowerCased.indexOf('chrome') >= 0) { // Chrome or Opera(Blink)
        if (lowerCased.indexOf('opr') >= 0) {
            results.browserName = 'Opera (Blink based)';
        }
        else results.browserName = 'Chrome';

        works.push({ browserKeyword: 'chrome/', indexOfKeyword: ' ' });
    }
    else if (lowerCased.indexOf('firefox') >= 0) { // Firefox
        results.browserName = 'Firefox';
        works.push({browserKeyword : 'firefox/'});
    }
    else {
        return {
            browserName : agent
          , version     : -1
        };
    }


    for (var idx = 0; idx < works.length; idx++) {
        browserKeyword = works[idx].browserKeyword;
        indexOfKeyword = works[idx].indexOfKeyword;
        browserNameIndex = lowerCased.indexOf(browserKeyword);

        var substringed = null;
        if (indexOfKeyword) substringed = lowerCased.substring(browserNameIndex, lowerCased.indexOf(indexOfKeyword, browserNameIndex)).substr(browserKeyword.length);
        else substringed = lowerCased.substring(browserNameIndex).substr(browserKeyword.length);
        results.version = $.trim(substringed);
        if ($.isNumeric(results.version)) break;
    }

    return results;
}

/**
 * 구버전 IE인지 확인 (기준 : 8 이하 (9 미만))
 * 
 * 일반적으로, IE9부터 웬만한 HTML5 요소들은 다 지원이 됨 (canvas 도 지원되므로 Chart.js도 사용 가능)
 * 특히, IE8이전에는 String.trim() 함수가 제공이 안 됨
 * IE7 이전에는 JSON 객체가 제공이 안 됨
 */
function fn_util_isOldInternetExplorer() {
    var _browserInfo = fn_util_getBrowserType();
    if(_browserInfo == null || typeof(_browserInfo) == 'undefined') return false;
    // IE 8 이하 (9 미만)
    return _browserInfo.browserName == 'Internet Explorer'
            && (! isNaN(_browserInfo.version))
            && Number(_browserInfo.version) < 9;
}

/**
 * 날짜 객체를 받아(넣지 않으면 오늘 날짜) 그 주의 첫 번째 날(일요일)과 마지막 날(토요일)을 각각 날짜 객체 FROM_DT, TO_DT로 담은 JSON 객체 반환
 * 
 */
function fn_util_getWeekPeriod(date) {
    if(date == null) date = new Date();
    if(typeof(date) == 'string') date = new Date(date);
    
    var resultObj = {};
    
    var clonedDate = new Date(date); // 객체 복사
    
    var first = date.getDate() - date.getDay();
    clonedDate.setDate(first);
    resultObj.FROM_DT = clonedDate;
    
    clonedDate = new Date(date);
    clonedDate.setDate(first + 6);
    resultObj.TO_DT   = clonedDate;
    
    return resultObj;
}

/**
 * 해당 문자열에서 원하는 텍스트를 다른 텍스트로 전부 치환합니다.
 * 
 * @param originalText : 사용할 문자열
 * @param target : 사용할 문자열 내에서, 대체되어야 할 기존 문자열
 * @param replacement : 대체할 새 문자열
 * @returns 처리된 문자열
 */
function fn_util_replaceAll(originalText, target, replacement) {
    return String(originalText).split(target).join(replacement);
}

/**
 * 어떤 문자열이 접미사로 끝나는지 여부를 반환합니다.
 * 출처 : http://stackoverflow.com/questions/280634/endswith-in-javascript
 * 
 * @param str : 검사할 문자열
 * @param suffix : 접미사
 */
function fn_util_endsWith(str, suffix) {
    return str.indexOf(suffix, str.length - suffix.length) !== -1;
}

/** 
   yyyy-MM-dd 형식의 문자열(선택 : HH24:MI 형식의 시간) 을 받아 그에 맞는 Date 객체를 반환합니다.
   (fn_util_parseDate(str) 와 기능이 비슷하므로 검토가 필요함)
*/
function fn_util_toDate(dateChar, hhmiChar) {
    if(fn_util_replaceAll(dateChar, '-', '').trim() == '') return null;
    
    var dateData = dateChar.split("-");
    var newDate = new Date(dateData[0], Number(dateData[1]) - 1, dateData[2]);
    if(hhmiChar) {
        var hhmi = hhmiChar.split(":");
        newDate.setHours(hhmi[0], hhmi[1]);
    }
    return newDate;
}

/** 기간 입력 요소에 실시간 Validation 을 적용합니다. (시간은 선택) */
function fn_util_setPeriodInput(fromDtSelector, toDtSelector, fromHhmiSelector, toHhmiSelector) {
    var $_fromDt = $(fromDtSelector);
    var $_toDt = $(toDtSelector);
    var $_fromHhmi = $(fromHhmiSelector);
    var $_toHhmi = $(toHhmiSelector);
    
    var fromDtVal = null;
    var toDtVal = null; 
    var fromHhmiVal = null;
    var toHhmiVal = null;
    
    fromDtVal = $(fromDtSelector).val();
    toDtVal = $(toDtSelector).val();
    if(fromHhmiSelector) fromHhmiVal = $(fromHhmiSelector).val();
    if(toHhmiSelector) toHhmiVal = $(toHhmiSelector).val();
    
    
    var checkDate = function() {
        var fromDt = null;
        if(fromHhmiSelector) fromDt = fn_util_toDate($_fromDt.val(), $_fromHhmi.val());
        else fromDt = fn_util_toDate($_fromDt.val());
        var toDt = null;
        if(toHhmiSelector) toDt = fn_util_toDate($_toDt.val(), $_toHhmi.val());
        else toDt = fn_util_toDate($_toDt.val());
        
        if(fromDt && toDt && fromDt >= toDt) {
            return false;
        }
        return true;
    };
    
    var fromDtChangeEvent = function() {
        if(! checkDate()) {
            alert('시작일자는 종료일자 이전이어야 합니다.');
            $_fromDt.val(fromDtVal);
        }
        fromDtVal = $(fromDtSelector).val();
    };
    var fromHmChangeEvent = function() {
        if(! checkDate()) {
            alert('같은 날짜인 경우 시작시간은 종료시간 이전이어야 합니다.');
            $_fromHhmi.val(fromHhmiVal);
        }
        fromHhmiVal = $(fromHhmiSelector).val();
    };
    var toDtChangeEvent = function() {
        if(! checkDate()) {
            alert('종료일자는 시작일자 이후이어야 합니다.');
            $_toDt.val(toDtVal);
        }
        toDtVal = $(toDtSelector).val();
    };
    
    var toHmChangeEvent = function() {
        if(! checkDate()) {
            alert('같은 날짜인 경우 종료시간은 시작시간 이후이어야 합니다.');
            $_toHhmi.val(toHhmiVal);
        }
        toHhmiVal = $(toHhmiSelector).val();
    };
    
    $_fromDt.change(fromDtChangeEvent);
    $_toDt.change(toDtChangeEvent);
    if(fromHhmiSelector) $_fromHhmi.change(fromHmChangeEvent);
    if(toHhmiSelector) $_toHhmi.change(toHmChangeEvent);
}

/**
 * 창 크기 변경 
 * 창 내부 영역의 크기를 지정해 창 크기를 변경 가능 --> 내부 영역 크기를 정확히 지정할 수 있음 (단, 스크롤바 크기는 반영이 안되므로 직접 보정해야 함)
 */
function fn_util_resizeInnerWidth(innerWidth, innerHeight) {
    var widthInt  = self.outerWidth  - self.innerWidth;
    var heightInt = self.outerHeight - self.innerHeight;
    self.resizeTo(innerWidth + widthInt, innerHeight + heightInt);
}

/**
 * URI 인코딩된 문자열을 디코딩해 반환
 * 브라우저에서 제공하는 decodeURIComponent 가 공백과 + 기호를 구분을 못해 모두 + 취급하는 현상 방지
 * 
 * 동작방식
 *   decodeURIComponent 를 호출하기 전의 내용에서 + 기호를 공백으로 변환함
 *   
 * 예) 
 *     var text = null;
 *     var text2 = null;
 *     text = "2017년 1월+3일"; // 2017년 1월+3일
 *     text = encodeURIComponent(text);  // 2017%EB%85%84+1%EC%9B%94%2B3%EC%9D%BC
 *     text2 = decodeURIComponent(text); // 2017년+1월+3일
 *     text2 = fn_util_decodeURI(text);  // 2017년 1월+3일
 *      
 * @param encodedText : encodeURIComponent 로 인코딩된 문자열
 * @returns 디코딩된 문자열
 */
function fn_util_decodeURI(encodedText) {
    return decodeURIComponent(encodedText.replace(new RegExp("\\+", "g"), " "));
}

/**
 * HTTP의 GET 형식 데이터를 JSON 으로 반환
 * 
 * @param data : GET 형식 매개변수 데이터
 * @returns JSON 형식 데이터
 */
function fn_util_jsonFromGet(data) {
    var jsonObj = {};
    if($.isPlainObject(data)) return data;
    if(data == '') return null;
    var paramData = data.split('&');
    for(var idx=0; idx<paramData.length; idx++) {
        var paramOne = paramData[idx].split('=');
        var paramKey = paramOne[0];
        var paramVal = fn_util_decodeURI(paramOne[1]);
        
        // 중복된 키값 검사 (예 : 체크박스 사용 시 같은 키값이 여러개가 나올 수 있음 --> 배열로 변경해야 함)
        var beforeObj = jsonObj[paramKey]; 
        if(beforeObj == null || typeof(beforeObj) == 'undefined') {   
            jsonObj[paramKey] = paramVal;
        }
        else if($.isArray(beforeObj)) {
            jsonObj[paramKey].push(paramVal);
        }
        else {
            var beforeVal = jsonObj[paramKey];
            jsonObj[paramKey] = [];
            jsonObj[paramKey].push(beforeVal);
            jsonObj[paramKey].push(paramVal);
        }
    }
    return jsonObj;
}

/**
 * 최상위 창의 페이지를 해당 URL로 이동시킵니다.
 * 
 * 최상단 브라우저 창의 경우 현재 창에서 페이지 이동이 되고,
 * 팝업창인 경우, 부모창이 페이지 이동이 되고
 * 팝업의 팝업인 경우, 부모의 부모, 최상위 창의 페이지 이동이 됩니다.
 * 
 * 재귀적으로 동작하기 때문에, 부모창에도 이 함수가 정의되어 있어야 정상 동작합니다.
 * 
 * TODO : 부모 창 또한 팝업인 상황에서, 부모 창이 닫히고 자식 창으로 차례가 돌아올 수 있는지 여부?
 * 
 * @param url : 최상위 창 페이지를 이동시킬 URL
 * @param closeAllExceptTop : true 시, 작업이 완료된 후 최상위 창을 제외한, 이 작업에 영향을 받은 팝업을 모두 닫습니다.
 * @param selfWin : 이 메소드를 실행할 팝업의 window 객체, 부모창(self.opener)을 지정해 이 메소드를 사용하면 이 메소드의 영향권은 부모창 혹은 그 상위 창에만 나타납니다. (null 시 self.opener 사용)
 */
function fn_util_movePageOnTopOpener(url, closeAllExceptTop, selfWin) {
    var openerObj = selfWin;
    if(openerObj == null || typeof(openerObj) == 'undefined') openerObj = self.opener;
    
    if(openerObj == null || typeof(openerObj) == 'undefined') { // 부모창이 없다 == 최상단 브라우저 창 ==> 단순 페이지 이동시키기 
        location.href = url;
    } else if(openerObj.fn_util_movePageOnTopOpener == null || typeof(openerObj.fn_util_movePageOnTopOpener) == 'undefined') { // 부모창은 있으나 이 함수가 없다 (외부 사이트에서 띄운 팝업이 이리로 들어온 것) ==> 부모창 페이지 이동시키기
        openerObj.location.href = url;
        if(closeAllExceptTop) self.close();
    } else { // 부모창도 있고 이 함수도 있다 ==> 최상단 브라우저 창의 페이지 이동을 위해 부모창의 이 함수 호출 (재귀적으로 이 함수가 호출되어 최상단 브라우저 창의 페이지가 이동됨)
        openerObj.fn_util_movePageOnTopOpener(url, closeAllExceptTop, openerObj.opener);
        if(closeAllExceptTop) self.close();
    }
}

// 아래의 쿠키 관련 함수를 이용해 해당 쿠키를 삭제합니다. (만료일을 오늘 이전으로 돌려 삭제)
function fn_util_removeCookie(name) {
    var argv = fn_util_removeCookie.arguments;
    var argc = fn_util_removeCookie.arguments.length;
    var path    = (1 < argc) ? argv[1] : '/';
    var domain  = (2 < argc) ? argv[2] : null;
    var secure  = (3 < argc) ? argv[3] : false;
    
    var expiredDate = new Date();
    expiredDate.setDate(expiredDate.getDate() - 1);
    fn_util_setCookie(name, '', expiredDate, path, domain, secure);
}

// 쿠키 목록 조회 (쿠키의 이름값 목록을 반환합니다.)
function fn_util_getCookieNames() {
    var results = [];
    var allCookies = document.cookie;
    var cookieBlocks = allCookies.split(';');
    for(var idx=0; idx<cookieBlocks.length; idx++) {
        var cookieBlock = cookieBlocks[idx];
        var cookieSplit = $.trim(cookieBlock).split('=');
        results.push($.trim(cookieSplit[0]));
    }
    return results;
}

// 쿠키를 전부 삭제합니다. (prefix 가 지정된 경우 prefix로 시작하는 이름값 전부 삭제)
function fn_util_removeAllCookies(prefix) {
    var argv = fn_util_removeAllCookies.arguments;
    var argc = fn_util_removeAllCookies.arguments.length;
    var path    = (1 < argc) ? argv[1] : '/';
    var domain  = (2 < argc) ? argv[2] : null;
    var secure  = (3 < argc) ? argv[3] : false;
    
    var cookieNames = fn_util_getCookieNames();
    for(var idx=0; idx<cookieNames.length; idx++) {
        if(fn_util_isEmpty(prefix)) fn_util_removeCookie(cookieNames[idx], path, domain, secure);
        else if(cookieNames[idx].indexOf(prefix) == 0) fn_util_removeCookie(cookieNames[idx], path, domain, secure);
    }
}

// 쿠키 관련 함수들
// 출처 : http://najackal.com.ne.kr/s-hompage/s-java/sturdy16.html

function fn_util_getCookieVal (offset) {
   var endstr = document.cookie.indexOf (";", offset);
   if (endstr == -1) endstr = document.cookie.length;
   return unescape(document.cookie.substring(offset, endstr));
}

function fn_util_getCookie(name) {
   var arg = name + "=";
   var alen = arg.length;
   var clen = document.cookie.length;
   var i = 0;
   while (i < clen) {   //while open
      var j = i + alen;
      if (document.cookie.substring(i, j) == arg)
         return fn_util_getCookieVal(j);
      i = document.cookie.indexOf(" ", i) + 1;
      if (i == 0) break; 
   }    //while close
   return null;
}

function fn_util_setCookie(name, value) {
   var argv = fn_util_setCookie.arguments;
   var argc = fn_util_setCookie.arguments.length;
   var expires = (2 < argc) ? argv[2] : null;
   var path = (3 < argc) ? argv[3] : null;
   var domain = (4 < argc) ? argv[4] : null;
   var secure = (5 < argc) ? argv[5] : false;
   document.cookie = name + "=" + escape (value) +
      ((expires == null) ? "" : 
         ("; expires=" + expires.toGMTString())) +
      ((path == null) ? "" : ("; path=" + path)) +
      ((domain == null) ? "" : ("; domain=" + domain)) +
      ((secure == true) ? "; secure" : "");
}
// // 여기까지가 쿠기 관련 함수

// 화면에서 복붙 방지하도록 해주는 함수
function fn_util_noCopyPaste() {
    window.document.oncontextmenu = new Function("return false"); 
    
    var ctrlDown = false;
    var ctrlKey = 17, vKey = 86, cKey = 67;
    $(document).keydown(function(e)
    {
        if (e.keyCode == ctrlKey) ctrlDown = true;
        
        if (ctrlDown && (e.keyCode == vKey || e.keyCode == cKey)) return false;
    }).keyup(function(e)
    {
        if (e.keyCode == ctrlKey) ctrlDown = false;
    });
    
}

/**
 * 숫자를 문자열로 변환합니다.
 * 자리수를 같이 받아, 숫자가 해당 자리수보다 작으면 앞에 0을 붙입니다.
 * 
 * @param number : 숫자 (정수)
 * @param digits : 자리수 (정수)
 * @returns 변환된 문자열
 */
function fn_util_padNumber(number, digits) {
    if(! $.isNumeric(number)) throw number + " 은/는 숫자가 아닙니다.";
    if(! $.isNumeric(digits)) throw digits + " 은/는 숫자가 아닙니다.";
    if(Number(number) != Math.round(Number(number))) throw number + " 은/는 정수가 아닙니다.";
    if(Number(digits) != Math.round(Number(digits))) throw digits + " 은/는 정수가 아닙니다.";
    var numberText = String(number);
    if(numberText.length > Number(digits)) throw "이미 숫자 " + numberText + " 이/가 지정한 자리수 " + digits + " 보다 큽니다.";
    while(numberText.length < Number(digits)) {
        numberText = '0' + numberText;
    }
    return numberText;
}

/**
 * 텍스트 영역의 커서가 있는 곳에 특정 내용을 끼워 넣습니다.
 * 
 * areaId : 텍스트 영역의 ID값
 * text   : 끼워넣을 텍스트
 * 
 * 출처 : http://stackoverflow.com/questions/1064089/inserting-a-text-where-cursor-is-using-javascript-jquery
 */
function fn_util_insertAtCaret(areaId, text) {
    var txtarea = document.getElementById(areaId);
    var scrollPos = txtarea.scrollTop;
    var caretPos = txtarea.selectionStart;

    var front = (txtarea.value).substring(0, caretPos);
    var back = (txtarea.value).substring(txtarea.selectionEnd, txtarea.value.length);
    txtarea.value = front + text + back;
    caretPos = caretPos + text.length;
    txtarea.selectionStart = caretPos;
    txtarea.selectionEnd = caretPos;
    txtarea.focus();
    txtarea.scrollTop = scrollPos;
}

/**
 * 날짜 범위 내에 있을 때에만 링크를 띄웁니다.
 * 
 * @param url : 대상 URL
 * @param isPopup : 링크 팝업으로 띄울지 여부
 * @param fromDt : 시작날짜
 * @param toDt : 종료 날짜
 * @param today : 오늘 날짜 (생략 시 브라우저 날짜 사용)
 */
function fn_util_linkFrom(url, isPopup, fromDt, toDt, today) {
    if(today == null || typeof(today) == 'undefined') today = new Date();
    if(typeof(today ) == 'string') today  = fn_util_parseDate(today);
    if(fromDt != null && typeof(fromDt) != 'undefined' && typeof(fromDt) == 'string') fromDt = fn_util_parseDate(fromDt);
    if(toDt   != null && typeof(toDt  ) != 'undefined' && typeof(toDt  ) == 'string') toDt   = fn_util_parseDate(toDt);
    
    if(fromDt != null && typeof(fromDt) != 'undefined' && today.getTime() < fromDt.getTime()) return false;
    if(toDt   != null && typeof(toDt  ) != 'undefined' && today.getTime() > toDt.getTime()  ) return false;
    
    url = String(url);
    if(isPopup) {
        window.open(url);
    } else {
        location.href = url;
    }
    return true;
}

/**
 * 객체를 복제합니다. 새 인스턴스가 만들어집니다. 단, 일반 객체 및 JSON 형식 객체만 가능합니다. 기본형 데이터나 함수는 그대로 반환됩니다.
 * 
 * @param obj : 복사할 값, 객체, 배열, ...
 * @returns 복사된 새 객체
 */
function fn_util_cloneObject(obj) {
    if($.isPlainObject(obj)) {
        var newObj = new Object();
        $.each(obj, function(key, val) {
            newObj[key] = fn_util_cloneObject(val);
        });
        return newObj;
    }
    else if($.isArray(obj)) { // 배열일 경우 - 내부 원소들까지 복제해 새 배열로 반환
        var newArr = [];
        for(var idx=0; idx<obj.length; idx++) {
            newArr.push(fn_util_cloneObject(obj[idx]));
        }
        return newArr;
    }
    else if(typeof(obj) == 'object' && obj instanceof Date) {
        return new Date(obj.getTime());
    }
    else return obj;
}

/**
 * JSON 객체 내 각 항목들을 NVL 처리합니다.
 * 예를 들어
 *   {
 *      A : 1,
 *      B : null,
 *      C : '19858'
 *   }
 * 위와 같은 JSON 객체가 이 함수를 거치게 되면
 *   {
 *      A : 1,
 *      B : '-',
 *      C : '19858'
 *   }
 * 으로 바뀝니다.
 * 
 * @param jsonArr : JSON 배열
 * @param alternatives : 항목이 null 혹은 undefined할 때 대신 넣을 값 (기본값 : '-')
 * @param keyArr : 추가적으로 존재해야 하는 키값 목록 (기본값 : 빈 배열)
 * @param checkNullFunc : NVL 검사함수 (true 반환 시 null 로 취급, 매개변수 하나(검사할 값)), 기본 함수 : null이거나 undefined, 문자열인 경우 공백인 경우에도 null 취급
 * @param copyObj : 작업 전 객체 복사 여부 (true 시 call by value, false 시 call by reference, 기본값 : false)
 */
function fn_util_nvlObject(jsonObj, alternatives, keyArr, checkNullFunc, copyObj) {
    if(alternatives == null || typeof(alternatives) == 'undefined') alternatives = '-';
    if(keyArr == null || typeof(keyArr) == 'undefined') keyArr = [];
    if(copyObj == null || typeof(copyObj) == 'undefined') copyObj = false;
    
    if(copyObj) jsonObj = fn_util_cloneObject(jsonObj);
    
    if(checkNullFunc == null || typeof(checkNullFunc) == 'undefined') {
        checkNullFunc = function(target) {
            return target == null || typeof(target) == 'undefined' || (typeof(target) == 'string' && fn_util_isEmpty(target));
        };
    }
    
    // 먼저 이미 들어가 있는 항목들부터 검사
    for(var jsonKey in jsonObj) {
        if(checkNullFunc(jsonObj[jsonKey])) jsonObj[jsonKey] = alternatives;
    }
    
    // keyArr 항목 검사
    for(var jsonKey in keyArr) {
        if(checkNullFunc(jsonObj[jsonKey])) jsonObj[jsonKey] = alternatives;
    }
    return jsonObj;
}

/**
 * JSON 배열(원소는 JSON객체) 내 원소 내 각 항목들을 NVL 처리합니다.
 * 예를 들어
 *   [{
 *      A : 1,
 *      B : null,
 *      C : '19858'
 *   }]
 * 위와 같은 JSON 배열이 이 함수를 거치게 되면
 *   [{
 *      A : 1,
 *      B : '-',
 *      C : '19858'
 *   }]
 * 으로 바뀝니다.
 * 
 * @param jsonArr : JSON 배열
 * @param alternatives : 항목이 null 혹은 undefined할 때 대신 넣을 값 (기본값 : '-')
 * @param keyArr : 추가적으로 존재해야 하는 키값 목록 (기본값 : 빈 배열)
 * @param checkNullFunc : NVL 검사함수 (true 반환 시 null 로 취급, 매개변수 하나(검사할 값)), 기본 함수 : null이거나 undefined, 문자열인 경우 공백인 경우에도 null 취급
 * @param copyObj : 작업 전 배열 복사 여부 (true 시 call by value, false 시 call by reference, 기본값 : false)
 */
function fn_util_nvlList(jsonArr, alternatives, keyArr, checkNullFunc, copyObj) {
    // 복사여부에 따라 복사 적용
    if(copyObj) jsonArr = fn_util_cloneObject(jsonArr);
    
    // 페이징 객체인 경우 내부 list 원소에 이 함수 동작 적용, 반환
    if(typeof(jsonArr) == 'object' && jsonArr.list != null && typeof(jsonArr.list) != 'undefined') {
        jsonArr.list = fn_util_nvlList(jsonArr.list, alternatives, keyArr, checkNullFunc, copyObj);
        return jsonArr;
    }
    // 그 외의 경우
    
    // 배열 각 원소 nvl 처리
    for(var idx=0; idx<jsonArr.length; idx++) {
        jsonArr[idx] = fn_util_nvlObject(jsonArr[idx], alternatives, keyArr, checkNullFunc, copyObj);
    }
    return jsonArr;
}

/** tbody 안의 모든 td, th 를 검사해 안의 텍스트 내용이 없으면 - 또는 지정된 텍스트로 대체 */
function fn_util_nvlTbody(tbodySelector, alternatives, exceptSelector) {
    if(typeof(alternatives) == 'undefined' || alternatives == null) alternatives = '-';
    
    var $jqueryObj = $(tbodySelector);
    $jqueryObj.find('td,th').each(function() {
        var $tdObj = $(this);
        
        if(typeof(exceptSelector) != 'undefined' && exceptSelector != null) {
            if($tdObj.is(exceptSelector)) return;
        }
        
        var insides = $tdObj.text();
        if(fn_util_isEmpty(insides)) $tdObj.text(alternatives);
    });
    return $jqueryObj;
}

/** 

Adobe Acrobat Reader 설치여부 확인

Adobe Acrobat Reader DC 버전에서도 동작하는것 확인
(간혹 브라우저 플러그인 설정이 망가져서 안나오는 경우도 있지만, Adobe Acrobat Reader 설치 복구하면 다시 동작함)

BSD 라이센스에 따라 수정은 가능하며, 원 라이센스 정보를 표시함

//
//http://thecodeabode.blogspot.com
//@author: Ben Kitzelman
//@license:  FreeBSD: (http://opensource.org/licenses/BSD-2-Clause) Do whatever you like with it
//@updated: 03-03-2013
//
*/
function fn_util_getAcrobatInfo() {
    var getBrowserName = function() {
        return this.name = this.name || function() {
            var userAgent = navigator ? navigator.userAgent.toLowerCase() : "other";

            if(userAgent.indexOf("chrome") > -1){
                return "chrome";
            } else if(userAgent.indexOf("safari") > -1){
                return "safari";
            } else if(userAgent.indexOf("msie") > -1 || navigator.appVersion.indexOf('Trident/') > 0){
                return "ie";
            } else if(userAgent.indexOf("firefox") > -1){
                return "firefox";
            } else {
                //return "ie";
                return userAgent;
            }
        }();
    };

    var getActiveXObject = function(name) {
        try { return new ActiveXObject(name); } catch(e) {}
    };

    var getNavigatorPlugin = function(name) {
        for(key in navigator.plugins) {
            var plugin = navigator.plugins[key];
            if(plugin.name == name) return plugin;
        }
    };

    var getPDFPlugin = function() {
        return this.plugin = this.plugin || function() {
            if(getBrowserName() == 'ie') {
                //
                // load the activeX control
                // AcroPDF.PDF is used by version 7 and later
                // PDF.PdfCtrl is used by version 6 and earlier
                return getActiveXObject('AcroPDF.PDF') || getActiveXObject('PDF.PdfCtrl');
            } else {
                return getNavigatorPlugin('Adobe Acrobat') || getNavigatorPlugin('Chrome PDF Viewer') || getNavigatorPlugin('WebKit built-in PDF');
            }
        }();
    };

    var isAcrobatInstalled = function() {
        return !!getPDFPlugin();
    };

    var getAcrobatVersion = function() {
        try {
            var plugin = getPDFPlugin();

            if(getBrowserName() == 'ie') {
                var versions = plugin.GetVersions().split(',');
                var latest = versions[0].split('=');
                return parseFloat(latest[1]);
            }

            if(plugin.version) return parseInt(plugin.version);
            return plugin.name;
        }
        catch(e) {
            return null;
        }
    };

    //
    // The returned object
    //
    return {
        browser: getBrowserName(),
        acrobat: isAcrobatInstalled() ? 'installed' : false,
        acrobatVersion: getAcrobatVersion()
    };
};

/**
 * 문자열에 매개변수를 삽입합니다. 문자열 안에, 매개변수가 들어갈 자리에 [%= 키%] 형식으로 표시를 해 사용하면 됩니다.
 * 
 * useJqueryTmpl 를 true 로 주면 jQuery tmpl 플러그인에서 지원하는 {%=  %}, {%if%} 등의 표현도 사용이 가능합니다.
 *    단, 문자열이 반드시 HTML 형식인 경우에만 정상적인 사용이 가능합니다.
 *    또한, tmpl 사용 과정에서 웹 컴포넌트로 변환되는 과정을 거치므로 따옴표가 쌍따옴표로 바뀌는 등의 추가 변경사항이 존재합니다.
 *
 * @param templateHTML : 매개변수가 들어갈 자리가 있는 문자열, 매개변수 자리에 [%=키%] 형식으로 표시한 문자열
 * @param paramObj : 매개변수들이 들어있는 JSON 객체
 * @param useJqueryTmpl : jQuery tmpl 플러그인 사용여부
 * @return 템플릿이 적용된 HTML 소스
 */
function fn_util_applyTemplate(templateHTML, paramObj, useJqueryTmpl) {
    if(paramObj == null) paramObj = {};
    var afterHTML = String(templateHTML);
    if ($.isArray(paramObj)) {
        var afterHTMLs = '';
        for (var idx = 0; idx < paramObj.length; idx++) {
            afterHTMLs += fn_util_applyTemplate(templateHTML, paramObj[idx]);
        }
        return afterHTMLs;
    }
    if (typeof (paramObj) == 'object') {
        var beforeHTML = afterHTML;
        afterHTML = '';
        var charLength = beforeHTML.length;
        var bigBlacOne = false;
        var bigBlacTwo = false;
        var keywordMode = false;
        var keyChar = '';
        var keywords = '';
        var closeBigOne = false;
        // 1글자씩 루프
        for (var idx = 0; idx < charLength; idx++) {
            var charOne = beforeHTML.charAt(idx);
            // [ 기호를 만났을 때 --> 표시하기
            if ((!bigBlacOne) && charOne == '[') {
                bigBlacOne = true;
                continue;
            }
            // [ 기호 한번 만나고 %를 만남 --> 키워드 수집모드
            if (bigBlacOne && charOne == '%') {
                bigBlacOne = false;
                bigBlacTwo = true;
                keywordMode = true;
                keywords = '';
                keyChar = '';
                continue;
            }
            // [ 기호 다음 %가 아닐 때 --> [ 하나로 취급하고 표시 풀기
            if(bigBlacOne && charOne != '%') {
                bigBlacOne = false;
                afterHTML += '[';
            }
            // 키캐릭터 받기
            if (keywordMode) {
                keyChar = charOne;
                keywordMode = false;
                continue;
            }
            // 키워드 수집모드에서 % 만남 --> 닫기 표시
            if (bigBlacTwo && charOne == '%') {
                closeBigOne = true;
                continue;
            }
            // 그렇지 않은 키워드 수집모드일 때
            if (bigBlacTwo && (!closeBigOne)) {
                keywords += charOne;
                continue;
            }
            // 닫기 표시된 상태에서 ] 만남 --> 키워드 수집모드 끝
            if (closeBigOne && charOne == ']') {
                closeBigOne = false;
                bigBlacOne = false;
                bigBlacTwo = false;
                keywordMode = false;
                keywords = keywords.trim();
                // %이후 연산자 처리 (추후 if 기능 지원예정)
                if (keyChar == '=') {
                    var showings = paramObj[keywords];
                    if (typeof (showings) == 'undefined' || showings == null)
                        showings = '';
                    afterHTML += showings;
                }
                else {
                    throw "동작 기호를 확인할 수 없습니다.";
                }
                continue;
            }
            afterHTML += charOne;
        }
    }
    if(useJqueryTmpl) {
        var $createdElement = $.tmpl(afterHTML, paramObj);
        afterHTML = $createdElement.wrap('<div>').parent().html();
    }
    
    return afterHTML;
};

/**
 * 비동기 방식으로 동작을 실행합니다.
 * 
 * TODO: 최신 브라우저일 때만 ECMAScript6 에서 제공하는 Promise 라이브러리를 사용하도록 변경
 */
function fn_util_workAsync(callbackFunc, delay) {
    if(typeof(delay) != 'number' || delay == null) delay = 1;
    var timerObj = window.setTimeout(function(){
        callbackFunc();
        window.clearTimeout(timerObj);
    }, delay);
};

/**
 * img 태그에 대체 이미지를 적용합니다.
 * 
 * 사용법
 *   img 태그에 data-altimg 라는 속성을 줍니다. 속성 값은 대체 이미지 경로로 넣습니다.
 *     예: data-altimg="${resourcesPath}/images/common/img_none.png"
 *   
 *   그리고, img 태그에 onerror 속성을 줍니다.
 *     예: onerror="fn_util_onErrorImg(this);"
 *     
 * 주의
 *   AJAX를 통해 이미지 경로를 가져와 자바스크립트로 경로를 넣어주는 경우 onerror 메소드가 호출이 안되는 경우가 있습니다.
 *   이 경우 자바스크립트 단에서 fn_util_IsImageOk() 메소드로 검사를 한번 해주고 대체 이미지 처리를 직접 해야 합니다.
 */
function fn_util_onErrorImg(selfImgObj) {
    $(selfImgObj).each(function(){
        var $this = $(this);
        if(! $this.is('img')) return;
        
        if(fn_util_IsImageOk($this)) return;
        
        var altImg = $this.attr('data-altimg');
        // if(fn_util_isEmpty(altImg)) return;
        if(fn_util_isEmpty(altImg) && typeof(contextPath) != 'undefined') {
            altImg = contextPath + "/resources/images/common/img_none.png";
        }
        if(fn_util_isEmpty(altImg)) return;
        
        var alreadyPrinted = $this.attr('data-altimgprint');
        if(fn_util_isEmpty(alreadyPrinted)) alreadyPrinted = 0;
        else alreadyPrinted = Number(alreadyPrinted);
        
        if(alreadyPrinted >= 2) {
            $this.off('error');
            return;
        }
        
        $this.attr('src', altImg);
        
        alreadyPrinted++;
        $this.attr('data-altimgprint', String(alreadyPrinted));
    });
    return false;
}

/**
 * img 태그에서 이미지를 제대로 불러왔는지 확인
 * 주의! 단일 이미지 태그만을 선택해야 합니다.
 * 
 * 출처 : http://stackoverflow.com/questions/1977871/check-if-an-image-is-loaded-no-errors-in-javascript
 */
function fn_util_IsImageOk(selector) {
    var img = $(selector)[0];
    var selLen = $(selector).length;
    if(selLen <= 0 || selLen >= 2) throw "단일 이미지 태그만을 선택해야 합니다.";
    
    var originalSrc = $(img).attr('src');
    if(fn_util_isEmpty(originalSrc)) {
        return false;
    }
    
    // During the onload event, IE correctly identifies any images that
    // weren’t downloaded as not complete. Others should too. Gecko-based
    // browsers act like NS4 in that they report this incorrectly.
    if (!img.complete) {
        return false;
    }

    // However, they do have two very useful properties: naturalWidth and
    // naturalHeight. These give the true size of the image. If it failed
    // to load, either of these should be zero.

    if (typeof img.naturalWidth !== "undefined" && img.naturalWidth === 0) {
        return false;
    }

    // No other way of checking: assume it’s ok.
    return true;
}

/**
 * JSON 객체들로 이루어진 배열에서 원하는 항목을 골라서(필터링) 배열로 반환합니다.
 *
 * @param array : 대상 배열
 * @param filterTargetField : 필터링할 대상 키값
 * @param filterValue : 필터링 검색어
 * @param filterMethod : 필터링 방식, S(일부 포함여부 검사), R(정규식), E(동일한지 검사) 지원, 기본값은 S (단, 검색어에 RegExp 객체가 들어오면 기본값은 R)
 * @returns 필터링에 대응하는 원소들의 배열
 */
function fn_util_filter(array, filterTargetField, filterValue, filterMethod) {
    if (filterMethod == null || typeof (filterMethod) != 'string') {
        filterMethod = 'S';
        if (filterValue instanceof RegExp)
            filterMethod = 'R';
    }
    filterMethod = filterMethod.toUpperCase();
    var filterResults = [];
    for (var idx = 0; idx < array.length; idx++) {
        var element = array[idx];
        var targetFieldVal = element[filterTargetField];
        if (targetFieldVal == null || typeof (targetFieldVal) == 'undefined')
            targetFieldVal = '';
        else
            targetFieldVal = String(targetFieldVal);
        if (filterMethod == 'R' || filterMethod == 'REGEX' || filterMethod == 'REGULAR EXPRESSION') {
            if (typeof (filterValue) == 'string')
                filterValue = new RegExp(filterValue);
            if (targetFieldVal.match(filterValue))
                filterResults.push(element);
        }
        else if (filterMethod == 'S' || filterMethod == 'SIMPLE') {
            filterValue = filterValue == null || typeof (filterValue) == 'undefined' ? '' : String(filterValue);
            if (targetFieldVal.indexOf(filterValue) >= 0)
                filterResults.push(element);
        }
        else if (filterMethod == 'E' || filterMethod == 'EQUAL') {
            filterValue = filterValue == null || typeof (filterValue) == 'undefined' ? '' : String(filterValue);
            if (targetFieldVal == filterValue)
                filterResults.push(element);
        }
        else {
            throw "지원하지 않는 필터링 메소드 : " + filterMethod;
        }
    }
    return filterResults;
}

/**
 * 팝업을 엽니다. 열 때 매개변수들을 POST 방식으로 전송합니다.
 * 이를 위해 비어 있는 form 태그가 필요합니다.
 * 이 form 객체를 반환합니다.
 * 
 * form 태그를 배치할 수 않고 사용하려면 formSelector 에 null 을 입력해 사용합니다.
 * 이 경우 body 태그가 하나 있어야 합니다. 이 body 태그 최하단에 임시 form이 생성되어 작업을 수행하고 임시 form을 지운 후 null을 반환합니다.
 * 
 * @param formSelector : 비어 있는 form 선택자 (이 form 은 다른 용도로 사용하지 않는 form이어야 합니다. display:none 인 div로 둘러싸서 배치하는 것을 권장)
 *                       null 사용 가능 (이 경우 body 태그 내 최하단으로 임시 form 요소가 생성되어 작업을 수행하고, 이후 skipSubmit가 true로 지정되지 않았다면 임시 form 요소를 삭제함)
 * @param url : 팝업 URL
 * @param params : 전송할 매개변수를 담은 JSON 객체 (단, '값'은 문자열 혹은 배열이어야 함, 객체를 넣을 경우 강제로 문자열로 변환되어 들어갑니다. 배열인 경우 키 이름에 []가 붙어 배열 원소 갯수만큼 전송됩니다)
 * @param skipSubmit : true 지정 시 form 을 submit하지 않습니다. 이 경우 팝업이 뜨지 않으며, 개발자가 직접 submit 해서 팝업을 열 수 있습니다. (기본값 : false, 이 경우 자동으로 팝업을 엽니다.)
 */
function fn_util_openByPost(formSelector, url, params, skipSubmit) {
    var $form = null;
    var isTemp = (formSelector == null);
    
    var todayDate = new Date(); // 되도록 겹치지만 않게 하는것이 목적, 궂이 서버시간 아니어도 됨
    var seconds = todayDate.getSeconds();
    var millis  = todayDate.getMilliseconds();
    
    if(isTemp) { // 대상 form이 지정되지 않은 경우
        var tempFormId = 'tempFrm_' + seconds + '' + millis;
        var $bodySelector = $('body');
        if($bodySelector.length <= 0) throw "body 태그가 배치되지 않았습니다.";
        $($bodySelector[0]).append("<form id='" + tempFormId + "'></form>");
        formSelector = "#" + tempFormId; 
    }
    $form = $(formSelector);
    $form.empty();
    $form.attr('action', url);
    $form.attr('target', '_blank');
    $form.attr('method', 'POST');
    
    // 히든 폼요소 생성
    $.each(params, function(key, val){
        if($.isArray(val)) {
            var newKey = key + '[]';
            var tempIds = [];
            for(var idx=0; idx<val.length; idx++) {
                var newId = key + '_' + seconds + '_temp_' + idx;
                $form.append(fn_util_applyTemplate("<input type='hidden' name='[%= key %]' id='[%= tempId %]'/>", {key: newKey, tempId : newId}));
                tempIds.push({id : newId, value : val[idx]});
            }
            for(var idx=0; idx<tempIds.length; idx++) {
                $("#" + tempIds[idx].id).val(tempIds[idx].value);
            }
        } else {
            $form.append(fn_util_applyTemplate("<input type='hidden' name='[%= key %]'/>", {key: key}));
        }
    });
    // 히든 폼요소에 데이터 삽입
    $.each(params, function(key, val){
        $form.find(fn_util_applyTemplate("[name='[%= key %]']", {key: key})).val(val);
    });
    
    if(!skipSubmit) {
        $form.submit();
        if(isTemp) {
            $form.remove();
            return null;
        }
    }
    return $form;
}


/**
 * 팝업 차단여부 감지
 * 출처 : http://h5bak.tistory.com/194
 * 
 * 주의사항
 *   브라우저에 따라, 잠시 팝업이 반짝 하고 떴다가 사라지는 현상이 있을 수도 있음 (실제로 팝업을 띄우고 제대로 떴는지 확인하는 방식이므로)
 *   원 블로그 게시자 말에 따르면, 크롬과 IE에서 테스트가 되었고,
 *      크롬의 경우 최초 한번만 체크해야 된다고 함
 */
function fn_util_isPopupBlocked(isNotBlockedCallback, isBlockedCallback) {
    var win = window.open('', 'win', 'width=1, height=1, scrollbars=yes, resizable=yes');

    if (win == null || typeof (win) == "undefined" || (win == null && win.outerWidth == 0) || (win != null && win.outerHeight == 0) || win.test == "undefined") {
        if(typeof(isBlockedCallback) == 'function') isBlockedCallback();
        if (win) win.close();
        return true;
    } else if (win) {
        if (win.innerWidth === 0){
            if(typeof(isBlockedCallback) == 'function') isBlockedCallback();
            if (win) win.close();
            return true;
        }
    }
    if (win) win.close();
    if(typeof(isNotBlockedCallback) == 'function') isNotBlockedCallback();
    return false;
}

/**
 * 현재 접속 프로토콜 타입을 확인합니다. SSL인지 구분이 가능합니다. 무조건 소문자만으로 된 영문으로 반환됩니다. 
 * 예: http, https
 */
function fn_util_getProtocol() {
    return fn_util_replaceAll(fn_util_replaceAll(String(location.protocol).toLowerCase(), ':', ''), '/', '');
}

function setCookie(name, value, expiredays){
	var todayDate = new Date();
	todayDate.setDate(todayDate.getDate() + expiredays);
	document.cookie = name + "=" + escape(value) + "; path=/; expires=" + todayDate.toGMTString() + ";";
}

function getCookie(name){
	var nameOfCookie = name + "=";
    var x = 0;
    while (x <= document.cookie.length){
        var y = (x + nameOfCookie.length);
        if (document.cookie.substring(x, y) == nameOfCookie){
        if ((endOfCookie = document.cookie.indexOf(";", y)) == -1){
        endOfCookie = document.cookie.length;
        }
        return unescape (document.cookie.substring(y, endOfCookie));
        }
        x = document.cookie.indexOf (" ", x) + 1;
        if (x == 0) break;
    }
    return "";
}

function fn_enterkey(fn) {
    if (window.event.keyCode == 13) {
    	eval(fn+"();");
    }
}