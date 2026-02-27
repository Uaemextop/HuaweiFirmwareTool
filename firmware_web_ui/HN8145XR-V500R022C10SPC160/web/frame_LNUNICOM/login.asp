<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1" />
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

    function dealDataWithFun(str) {
      if (typeof str === 'string' && str.indexOf('function') === 0) {
        return Function('"use strict";return (' + str + ')')()();
      }
      return str;
    }

    var FailStat = '<%HW_WEB_GetLoginFailStat();%>';
    var LoginTimes = '<%HW_WEB_GetLoginFailCount();%>';
    var ModeCheckTimes = '<%HW_WEB_GetModPwdFailCnt();%>';
    var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
    var Language = "chinese";
    var UserLeveladmin = 0;
    var devicename = '<%GetAspPoductName();%>';
    var zqcu = '<%HW_WEB_GetFeatureSupport(HW_FEATURE_ZQCU);%>';
    if (zqcu == 1) {
        devicename = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
        var bponAPFttrDesc = 'Edge ONU';
        var bponDescCache = 'Edge ONU';
        var isBPON866F = '<%HW_WEB_GetFeatureSupport(AMP_FT_IS_866F);%>';
        var Var_DefaultLang = '<%HW_WEB_GetCurrentLanguage();%>';
        var isBponMainOnt = '<%HW_WEB_GetFeatureSupport(FT_FTTR_MAIN_ONT);%>';
        if(isBponMainOnt != '1') {
            bponAPFttrDesc = 'AP';
            bponFttrDesc = 'AP';
        } else if(isBPON866F != '1') {
            bponAPFttrDesc = Var_DefaultLang == 'chinese' ? '从FTTR' : 'slaveFTTR';
            bponFttrDesc = 'FTTR';
        }
        sessionStorage.bponAPDescCache = bponAPFttrDesc;
        sessionStorage.bponDescCache = bponFttrDesc;
    }
    document.title = devicename;

    var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
    var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
    var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
    var locklefttimerhandle;
    var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
    var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
    var APPVersion = '<%HW_WEB_GetAppVersion();%>';
    var isSupportOptic = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_OPTIC);%>';
    var stbport = '<%HW_WEB_GetSTBPort();%>';
    var UpUserPortID = '<%HW_WEB_GetCurUpUserPortID();%>';
    var P2pFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_P2P);%>';
    var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
    var jiuzhouFlag = '<%WEB_GetJiuZhouFlag();%>';
    var FTTR2BWEB = '<%HW_WEB_GetFeatureSupport(FT_WEB_FTTR2B);%>';
    var fttr_login = false;
    function stOpticInfo(domain, transOpticPower, revOpticPower) {
      this.domain = domain;
      this.transOpticPower = transOpticPower;
      this.revOpticPower = revOpticPower;
    }

    var opticInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic,TxPower|RxPower,stOpticInfo);%>;
    var opticInfo = opticInfos[0];

    function GEInfo(domain, Status) {
      this.domain = domain;
      this.Status = Status;
    }

    var geInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig,Link,GEInfo);%>;

    function AreaRelationInfo(ChineseDes, E8CArea) {
      this.ChineseDes = ChineseDes;
      this.E8CArea = E8CArea;
    }

    var AreaRelationInfos = new Array();
    var userEthInfos = new Array(new AreaRelationInfo("重庆", "023"),
      new AreaRelationInfo("四川", "028"),
      new AreaRelationInfo("云南", "0871"),
      new AreaRelationInfo("贵州", "0851"),
      new AreaRelationInfo("北京", "010"),
      new AreaRelationInfo("上海", "021"),
      new AreaRelationInfo("天津", "022"),
      new AreaRelationInfo("安徽", "0551"),
      new AreaRelationInfo("福建", "0591"),
      new AreaRelationInfo("甘肃", "0931"),
      new AreaRelationInfo("广东", "020"),
      new AreaRelationInfo("广西", "0771"),
      new AreaRelationInfo("海南", "0898"),
      new AreaRelationInfo("河北", "0311"),
      new AreaRelationInfo("河南", "0371"),
      new AreaRelationInfo("湖北", "027"),
      new AreaRelationInfo("湖南", "0731"),
      new AreaRelationInfo("吉林", "0431"),
      new AreaRelationInfo("江苏", "025"),
      new AreaRelationInfo("江西", "0791"),
      new AreaRelationInfo("辽宁", "024"),
      new AreaRelationInfo("宁夏", "0951"),
      new AreaRelationInfo("青海", "0971"),
      new AreaRelationInfo("山东", "0531"),
      new AreaRelationInfo("山西", "0351"),
      new AreaRelationInfo("陕西", "029"),
      new AreaRelationInfo("西藏", "0891"),
      new AreaRelationInfo("新疆", "0991"),
      new AreaRelationInfo("浙江", "0571"),
      new AreaRelationInfo("黑龙江", "0451"),
      new AreaRelationInfo("内蒙古", "0471"),
      null);

    function GetE8CAreaByCfgFtWord(userEthInfos, name) {
      var length = userEthInfos.length;

      for (var i = 0; i < length - 1; i++) {
        if (name == userEthInfos[i].E8CArea) {
          return userEthInfos[i].ChineseDes;
        }
      }

      return null;
    }

    var CfgFtChineseArea = GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea);

    function stResultInfo(domain, Result, Status) {
      this.domain = domain;
      this.Result = Result;
      this.Status = Status;
    }

    var stResultInfos = new stResultInfo("0", "0", "0");

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

        if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
          document.getElementById('regdevice').onclick = function () { }
        }
        else {
          if (('GDCU' != CfgFtWord.toUpperCase())
            && ('LNCU' != CfgFtWord.toUpperCase())
            && ('BJCU' != CfgFtWord.toUpperCase())
            && ('BJUNICOM' != CfgFtWord.toUpperCase())) {
            document.getElementById('regdevice').onclick = function () { }
          }
        }
        document.getElementById('btnSubmit').onclick = function () { }
        document.getElementById('adminSubmit').onclick = function () { }
      }
      else if (((LoginTimes >= errloginlockNum) || (ModeCheckTimes >= errloginlockNum)) && parseInt(LockLeftTime) > 0) {
        var html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
        SetDivValue("DivErrPage", html);
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);

        if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
          document.getElementById('regdevice').onclick = function () { }
        }
        else {
          if (('GDCU' != CfgFtWord.toUpperCase())
            && ('LNCU' != CfgFtWord.toUpperCase())
            && ('BJCU' != CfgFtWord.toUpperCase())
            && ('BJUNICOM' != CfgFtWord.toUpperCase())) {
            document.getElementById('regdevice').onclick = function () { }
          }
        }

        document.getElementById('btnSubmit').onclick = function () { }
        document.getElementById('adminSubmit').onclick = function () { }
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
      Form.addParameter('Language', Language);
      document.cookie = cookie2;
      Username.disabled = true;
      Password.disabled = true;
      setCookie("MenuJumpIndex", "0");
      Form.addParameter('x.X_HW_Token', cnt);
      if (fttr_login) {
        Form.setAction('/login.cgi?&SubmitType=fttr2b');
      } else {
        Form.setAction('/login.cgi');
      }
      Form.submit();
      return true;
    }

    function AdminSubmitForm() {
      fttr_login = true;
      sessionStorage.setItem("loginName", document.getElementById('txt_Username').value);
      sessionStorage.setItem("pathName", window.location.pathname);
      SubmitForm();
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
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        document.getElementById('tabuserinfo').style.marginLeft = "475px";
        document.getElementById('username_txt').innerHTML = "管理员账户";
        document.getElementById('username_txt').style.marginTop = '27px';
        document.getElementById('userpwd_txt').style.marginTop = '28px';
        document.getElementById('username_txt').style.marginLeft = '481px';
        document.getElementById('userpwd_txt').style.marginLeft = '499px';
        document.getElementById('userpwd_txt').innerHTML = "密 码";

      }
      else {
        document.getElementById('username_txt').innerHTML = "用 户 账 户";
        document.getElementById('userpwd_txt').innerHTML = "用 户 密 码";
      }

      document.getElementById('AccountPain').style.background = "url('/images/userinfo.gif')";
      document.getElementById('PwdPain').style.background = "url('/images/userinfo.gif')";

      document.getElementById('txt_Username').focus();
      clearInterval(locklefttimerhandle);
      var UserLeveladmin = '<%HW_WEB_CheckUserInfo();%>';

      if (CfgFtWord.toUpperCase() != 'UNICOMBRIDGE') {
        if (CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE' && CfgFtWordArea.toUpperCase() != '') {
          document.getElementById('ChooseInfo').innerHTML = CfgFtChineseArea;
        }
      }

      if ((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0)) {
        document.getElementById('loginfail').style.display = '';
        setErrorStatus();
      }

      if ("1" == FailStat || (ModeCheckTimes >= errloginlockNum)) {
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
      if ((LoginTimes != null && LoginTimes != '' && LoginTimes > 0) || (ModeCheckTimes >= errloginlockNum)) {
        setErrorStatus();
      }
    }

    function getRegStatus() {

      $.ajax({
        type: "POST",
        async: false,
        cache: false,
        url: "asp/GetRegStatusInfo.asp",
        success: function (data) {
          stResultInfos = dealDataWithFun(data);

        }
      });
    }

    function JumpToReg() {
      getRegStatus();
      var Infos = stResultInfos[0];
      if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)))) {
        window.location = "/loidgregsuccess.asp";
      }
      else {
        window.location = "/loidreg.asp";
      }
    }

    function setRxPowerHtml() {
      if (0 != isSupportOptic) {
        if (opticInfo == null) {
          document.write('<div id="main_RxPower" style="  margin-left: 100px; position: absolute; margin-top: 250px; font-family:Arial;font-size:12px;">接收光功率：未知</div>');
          document.write('<div id="main_TxPower" style="  margin-left: 100px; position: absolute; margin-top: 270px; font-family:Arial;font-size:12px;">发送光功率：未知</div>');
        }
        else {
          document.write('<div id="main_RxPower" style="  margin-left: 100px; position: absolute; margin-top: 250px; font-family:Arial;font-size:12px;">接收光功率：' + opticInfo.revOpticPower + ' dBm</div>');
          document.write('<div id="main_TxPower" style="  margin-left: 100px; position: absolute; margin-top: 270px; font-family:Arial;font-size:12px;">发送光功率：' + opticInfo.transOpticPower + ' dBm</div>');
        }
      }

      document.write('<div id="main_Lan" style="  margin-left: 98px; position: absolute; margin-top: 290px; font-family:Arial;font-size:12px;"></div>');

      var lanDiv = getElementById('main_Lan');
      var lanHtml = '<table style = "font-family:Arial;font-size:12px;"><tr><td>灯名称&nbsp;&nbsp</td>';
      for (var i = 0; i < geInfos.length - 1; i++) {
        if ((('1' == P2pFlag) && ((i + 1) == UpUserPortID)) || (stbport == (i + 1))) {
          continue;
        }

        lanHtml += '<td>LAN' + (i + 1) + '&nbsp;&nbsp' + '</td>';
      }
      lanHtml += '</tr><tr><td>状态</td>';

      for (var i = 0; i < geInfos.length - 1; i++) {
        if ((('1' == P2pFlag) && ((i + 1) == UpUserPortID)) || (stbport == (i + 1))) {
          continue;
        }

        if (geInfos[i].Status == 1) {

          lanHtml += '<td style = "text-align:center;"><img src="/images/lighton.jpg"></td>';
        }
        else {
          lanHtml += '<td style = "text-align:center;"><img src="/images/lightdown.jpg"></td>';
        }
      }
      lanHtml += '</tr></table>';

      lanDiv.innerHTML = '';
      lanDiv.innerHTML = lanHtml;
    }

  </script>
</head>

<body onLoad="LoadFrame();">
  <script type="text/javascript" language="javascript">
    if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
      if ('LNCU' == CfgFtWord.toUpperCase()) {
        document.write('<div id="main_wrapper" style="background-image:url(/images/cu_loginbg.jpg);width:950px;height:500px; background-repeat: no-repeat;">');
        if (jiuzhouFlag != '1') {
          document.write('<div id="main_hwlog" style="  margin-left: 200px; position: absolute; margin-top: 70px; z-index: 1111; width: 100px;height: 80px;background-image:url(/images/logo.gif); background-repeat: no-repeat;"></div>');
        }
        document.write('<div id="maie8cdeviceinfo.aspn_underlogtxt" style="  margin-left: 170px; position: absolute; margin-top: 150px; font-family:Arial;font-size:12px;font-weight:bolder;">设备型号：' + ProductName + '</div>');
        setRxPowerHtml();
      }
      else {
        document.write('<div id="main_wrapper" style="background-image:url(/images/loginbg.gif);width:950px;height:500px; background-repeat: no-repeat;">');
      }
    }
    else {
      document.write('<div  id="main_wrapper" style="background-image:url(/images/loginuserbg.gif);width:935px;height:417px; background-repeat: no-repeat;">');
      if ('LNCU' == CfgFtWord.toUpperCase()) {
        if (jiuzhouFlag != '1') {
          document.write('<div id="main_hwlog" style="  margin-left: 200px; position: absolute; margin-top: 70px; z-index: 1111; width: 100px;height: 80px;background-image:url(/images/logo.gif); background-repeat: no-repeat;"></div>');
        }
        document.write('<div id="main_underlogtxt" style="  margin-left: 170px; position: absolute; margin-top: 150px; font-family:Arial;font-size:12px;font-weight:bolder;">设备型号：' + ProductName + '</div>');

        setRxPowerHtml();
      }
    }
  </script>

  <div>
    <div
      style="position:absolute; top:192px;margin-left:530px;height:20px;font-family: 'SimHei';font-size:12px;font-weight:bolder;color:#414141;"
      id="username_txt"></div>
    <div
      style="position:absolute; top:254px;margin-left:530px;height:20px;font-family: 'SimHei';font-size:12px;font-weight:bolder;color:#414141;"
      id="userpwd_txt"></div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <script type="text/javascript" language="javascript">
        if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
          document.write('<td width="100%" style="height:175px"><table  border="0" cellpadding="0" cellspacing="0" width="100%"><td width="100%" style="height:10px"></td></table><span id="ChooseInfo" style="margin-left:45px;font-weight:bolder;font-size:18px;font-family:Arial;color:red;text-align:center;"></span></td>');
        }
        else {
          document.write('<td width="100%" style="height:148px"><table  border="0" cellpadding="0" cellspacing="0" width="100%"><td width="100%" style="height:30px"></td></table><span id="ChooseInfo" style="margin-left:30px;font-weight:bolder;font-size:18px;font-family:Arial;color:red;text-align:center;"></span></td>');

        }

      </script>
    </table>

    <table id="tabuserinfo" border="0" cellpadding="0" cellspacing="0" style="margin-left:525px;">
      <tr>
        <td id="AccountPain" style="width:242px;height:42px; background-repeat: no-repeat;">
          <input
            style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:85px; width:100px"
            id="txt_Username" name="txt_Username" type="text" maxlength="32">
        </td>
      </tr>
      <tr>
        <td style="height:20px;"></td>
      </tr>
      <tr>
        <td id="PwdPain" style="width:242px;height:42px; background-repeat: no-repeat;">
          <input
            style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:85px; width:100px"
            autocomplete="off" id="txt_Password" name="txt_Password" type="password" maxlength="127">
        </td>
      </tr>
    </table>
  </div>

  <div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
      <td width="100%" style="height:25px"></td>
    </table>
    <script type="text/javascript" language="javascript">
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        var loginbtnMargin = 400;
        if (FTTR2BWEB != "1") {
          loginbtnMargin += 50;
        }
        if (IsMaintWan == 1) {
          loginbtnMargin += 50;
        }
        document.write('<img src="/images/loginbtn.gif" style="margin-left:' + loginbtnMargin + 'px;" id="btnSubmit" name="btnSubmit" value="" onclick="SubmitForm();"/>');
        document.write('<img src="/images/resetbtn.gif" style="margin-left:20px;" id="btnCancel" name="btnCancel" value="" onclick="canceltext();"/>');
        if (FTTR2BWEB == "1") {
          document.write('<img src="/images/loginbtn_admin.gif" style="margin-left:20px;" id="adminSubmit" name="adminSubmit" value="" onclick="AdminSubmitForm();"/>');
        }
        getRegStatus();
        var Infos = stResultInfos[0];
        if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)))) {
          if (1 == IsMaintWan) {
            document.write('<img style="margin-left:48px;" id="regdevice" name="regdevice" value="" hidden="hidden"/>');
          }
          else {
            if ((CfgFtWord.toUpperCase() == 'LNCU') || (CfgFtWord.toUpperCase() == 'HUNCU')) {
              document.write('<img src="/images/regdevicebtn_gray.gif" style="margin-left:20px;" id="regdevice" name="regdevice" value=""/>');
            }
            else {
              document.write('<img src="/images/regdevicebtn.gif" style="margin-left:20px;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>');
            }
          }
        }
        else {
          if (1 == IsMaintWan) {
            document.write('<img style="margin-left:20px;" id="regdevice" name="regdevice" value="" hidden="hidden"/>');
          } else {
            document.write('<img src="/images/regdevicebtn.gif" style="margin-left:20px;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>');
          }
        }
      }
      else {
        var loginbtnMargin = 450;
        if (FTTR2BWEB != "1") {
          loginbtnMargin += 50;
        }
        if (IsMaintWan == 1) {
          loginbtnMargin += 50;
        }
        document.write('<img src="/images/loginbtn.gif" style="margin-left:' + loginbtnMargin + 'px;" id="btnSubmit" name="btnSubmit" value="" onclick="SubmitForm();"/>');
        document.write('<img src="/images/resetbtn.gif" style="margin-left:20px;" id="btnCancel" name="btnCancel" value="" onclick="canceltext();"/>');
        if (FTTR2BWEB == "1") {
          document.write('<img src="/images/loginbtn_admin.gif" style="margin-left:20px;" id="adminSubmit" name="adminSubmit" value="" onclick="AdminSubmitForm();"/>');
        }
        if (('GDCU' != CfgFtWord.toUpperCase())
          && ('LNCU' != CfgFtWord.toUpperCase())
          && ('BJCU' != CfgFtWord.toUpperCase())
          && ('BJUNICOM' != CfgFtWord.toUpperCase())) {
          if (1 == IsMaintWan) {
            document.write('<img style="margin-left:20px;" id="regdevice" name="regdevice" value="" hidden="hidden"/>');
          } else {
            document.write('<img src="/images/regdevicebtn.gif" style="margin-left:20px;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>');
          }
        }


      }
    </script>

  </div>

  <div id="loginfail" style="display: none">
    <table border="0" cellpadding="0" cellspacing="5" height="33" width="100%">
      <tr>
        <td width="45%" height="30"></td>
        <td align="center" height="21" width="43%">
          <script type="text/javascript" language="javascript">
            if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
              document.write('<label id="DivErrPage" style="color:red;font-size:12px;font-family:Arial;"/>');
            }
            else {
              document.write('<label id="DivErrPage" style="margin-left:130px;color:red;font-size:12px;font-family:Arial;"/>');
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