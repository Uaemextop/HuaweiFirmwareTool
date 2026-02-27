<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Cache-Control" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title></title>
  <link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>" media="all" rel="stylesheet" />
  <style type="text/css">
    #first {
      background-color: white;
      height: 25px;
      text-align: center;
      color: red;
      position: absolute;
      width: 380px;
      top: 312px;
    }
  </style>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <script language="JavaScript" type="text/javascript">

    var FailStat = '<%HW_WEB_GetLoginFailStat();%>';
    var LoginTimes = '<%HW_WEB_GetLoginFailCount();%>';
    var ModeCheckTimes = '<%HW_WEB_GetModPwdFailCnt();%>';
    var Language = "chinese";
    var UserLeveladmin = 0;
    var devicename = '<%GetAspPoductName();%>';
    document.title = devicename;

    var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
    var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
    var locklefttimerhandle;

    function showlefttime() {
      if (LockLeftTime <= 0) {
        if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
          window.location = "/CU.HTML";
        }
        else {
          window.location = "/login.asp";
        }

        return;
      }

      var html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
      SetDivValue("DivErrPage", html);
      LockLeftTime = LockLeftTime - 1;
    }

    function setErrorStatus() {
      clearInterval(locklefttimerhandle);
      if ('1' == FailStat) {
        if (ModeCheckTimes >= errloginlockNum) {
          SetDivValue("DivErrPage", "您尝试的次数已超出限制。");
        }
        else {
          SetDivValue("DivErrPage", "您登录失败的次数已超出限制。");
        }

        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);

        document.getElementById('btnSubmit').onclick = function () { }
      }
      else if (((LoginTimes >= errloginlockNum) || (ModeCheckTimes >= errloginlockNum)) && parseInt(LockLeftTime) > 0) {
        var html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
        SetDivValue("DivErrPage", html);
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);

        document.getElementById('btnSubmit').onclick = function () { }
        locklefttimerhandle = setInterval('showlefttime()', 1000);
      }
      else if (LoginTimes > 0 && LoginTimes < errloginlockNum) {
        SetDivValue("DivErrPage", "用户名或密码错误，请重新登录。");
      }
      else {
        document.getElementById('loginfail').style.display = 'none';
      }

    }

    function SubmitForm() {
      var Username = document.getElementById('txt_Username');
      var Password = document.getElementById('txt_Password');
      var appName = navigator.appName;
      var version = navigator.appVersion;

      if (appName == "Microsoft Internet Explorer") {
        var versionNumber = version.split(" ")[3];
        if (parseInt(versionNumber.split(";")[0]) <= 6) {
          alert("不支持IE6.0及以下版本。");
          return false;
        }
      }

      if (Username.value == "") {
        alert("用户名不能为空。");
        Username.focus();
        return false;
      }

      if (Password.value == "") {
        alert("密码不能为空。");
        Password.focus();
        return false;
      }

      var cnt;

      $.ajax({
        type: "POST",
        async: false,
        cache: false,
        url: '/asp/GetRandCount.asp',
        success: function (data) {
          cnt = data;
        }
      });

      var Form = new webSubmitForm();
      var cookie2 = "Cookie=body:" + "Language:" + Language + ":" + "id=-1;path=/";
      Form.addParameter('UserName', Username.value);
      Form.addParameter('PassWord', base64encode(Password.value));
      document.cookie = cookie2;
      Username.disabled = true;
      Password.disabled = true;
      setCookie("MenuJumpIndex", "0");
      Form.addParameter('x.X_HW_Token', cnt);
      Form.setAction('/login.cgi');
      Form.submit();
      return true;
    }

    function canceltext() {
      document.getElementById('txt_Username').value = "";
      document.getElementById('txt_Password').value = "";
    }

    function IsIEBrower(num) {
      var ua = navigator.userAgent.toLowerCase();
      var isIE = ua.indexOf("msie") > -1;
      var safariVersion;
      if (isIE) {
        safariVersion = ua.match(/msie ([\d.]+)/)[1];
        var sa = parseInt(safariVersion);
        if (safariVersion <= num) {
          alert("您当前使用的IE浏览器版本过低（不支持IE6/7/8），必须升级到IE9及以上版本，以便正常访问WEB页面。");
        }
      }
    }

    function LoadFrame() {
      clearInterval(locklefttimerhandle);
      var UserLeveladmin = '<%HW_WEB_CheckUserInfo();%>';

      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        document.getElementById('username_txt').innerHTML = "管理员账户";
        document.getElementById('username_txt').style.marginLeft = '485px';
        document.getElementById('userpwd_txt').style.marginLeft = '502px';
        document.getElementById('userpwd_txt').innerHTML = "密 码";
        document.getElementById('btnSubmit').style.marginLeft = '485px';
        document.getElementById('tabuserinfo').style.marginLeft = '480px';
        document.getElementById('btnSubmit_txt').style.marginLeft = '506px';
        document.getElementById('btnCancel_txt').style.marginLeft = '641px';
        document.getElementById('btnSubmit_txt').style.marginTop = '25px';
        document.getElementById('btnCancel_txt').style.marginTop = '25px';
      }
      else {
        document.getElementById('username_txt').innerHTML = "用 户 账 户";
        document.getElementById('userpwd_txt').innerHTML = "用 户 密 码";
        document.getElementById('tabuserinfo').style.marginTop = '-25px';
        document.getElementById('userpwd_txt').style.marginTop = '-24px';
        document.getElementById('username_txt').style.marginTop = '-24px';
        document.getElementById('btnSubmit').style.marginLeft = '535px';
      }

      document.getElementById('txt_Username').focus();
      if ((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0)) {
        document.getElementById('loginfail').style.display = '';
        setErrorStatus();
      }
      if ("1" == FailStat) {
        document.getElementById('loginfail').style.display = '';
        setErrorStatus();
      }
      init();

      if ((UserLeveladmin == '0')) {
        alert("当前用户不允许登录。");
        return false;
      }
    }

    function init() {
      if (document.addEventListener) {
        document.addEventListener("keypress", onHandleKeyDown, false);
      } else {
        document.onkeypress = onHandleKeyDown;
      }
    }
    function onHandleKeyDown(event) {
      var e = event || window.event;
      var code = e.charCode || e.keyCode;

      if (code == 13) {
        SubmitForm();
      }
    }
    function onChangeLanguage(language) {
      Language = language;
      if ((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0)) {
        setErrorStatus();
      }
    }

  </script>
</head>

<body onLoad="LoadFrame();">
  <script type="text/javascript" language="javascript">
    if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
      document.write('<div id="main_wrapper" style="background-image:url(/images/cu_loginadminbg.jpg);width:950px;height:500px; background-repeat: no-repeat;">');
    }
    else {
      document.write('<div  id="main_wrapper" style="background-image:url(/images/cu_loginuserbg.jpg);width:935px;height:417px; background-repeat: no-repeat;">');
    }
  </script>
  <div>
    <div
      style="position:absolute; top:208px;margin-left:520px;height:20px;font-family: 'Simhei';font-size:12px;font-weight:bolder;color:#414141;"
      id="username_txt"></div>
    <div
      style="position:absolute; top:271px;margin-left:520px;height:20px;font-family: 'Simhei';font-size:12px;font-weight:bolder;color:#414141;"
      id="userpwd_txt"></div>
    <div
      style="position:absolute; top:296px;margin-left:555px;height:20px;font-family: 'Simhei';font-size:15px;font-weight:bolder;color:#414141; cursor:default;"
      id="btnSubmit_txt" onClick="SubmitForm();">登 录</div>
    <div
      style="position:absolute; top:296px;margin-left:691px;height:20px;font-family: 'Simhei';font-size:15px;font-weight:bolder;color:#414141; cursor:default;"
      id="btnCancel_txt" onClick="canceltext();">重 置</div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <td width="100%" style="height:165px"></td>
    </table>

    <table id="tabuserinfo" border="0" cellpadding="0" cellspacing="0" style="margin-left:515px;">
      <tr>
        <td id="AccountPain"
          style="background-image:url(/images/userinfo.gif);width:242px;height:42px; background-repeat: no-repeat;">
          <input
            style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:85px; width:100px"
            id="txt_Username" name="txt_Username" type="text" maxlength="31">
        </td>
      </tr>
      <tr>
        <td style="height:20px;"></td>
      </tr>
      <tr>
        <td id="PwdPain"
          style="background-image:url(/images/userinfo.gif);width:242px;height:42px; background-repeat: no-repeat;">
          <input
            style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:85px; width:100px"
            id="txt_Password" name="txt_Password" type="password" maxlength="127">
        </td>
      </tr>
    </table>

  </div>

  <div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <td width="100%" style="height:18px"></td>
    </table>
    <img src="/images/loginbtn_cut.gif" style="margin-left:485px;" id="btnSubmit" name="btnSubmit" value=""
      onClick="SubmitForm();" />
    <img src="/images/loginbtn_cut.gif" style="margin-left:48px;" id="btnCancel" name="btnCancel" value=""
      onClick="canceltext();" />
  </div>

  <div id="loginfail" style="display: none">
    <table border="0" cellpadding="0" cellspacing="5" height="33" width="100%">
      <tr>
        <td width="45%" height="30"></td>
        <td align="center" height="21" width="42%">
          <script type="text/javascript" language="javascript">
            if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
              document.write('<label id="DivErrPage" style="color:red;font-size:12px;font-family:Arial;"/>');
            }
            else {
              document.write('<label id="DivErrPage" style="margin-left:120px;color:red;font-size:12px;font-family:Arial;"/>');
            }
          </script>
        </td>
        <td width="30%"></td>
      </tr>
    </table>
  </div>
  </div>
</body>

</html>