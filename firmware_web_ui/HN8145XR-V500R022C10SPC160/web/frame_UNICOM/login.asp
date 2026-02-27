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
    var Language = "chinese";
    var UserLeveladmin = 0;
    var devicename = '<%GetAspPoductName();%>';
    document.title = devicename;

    var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
    var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
    var locklefttimerhandle;
    var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
    var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
    var APPVersion = '<%HW_WEB_GetAppVersion();%>';
    var isSupportOptic = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_OPTIC);%>';
    var stbport = '<%HW_WEB_GetSTBPort();%>';
    var UpUserPortID = '<%HW_WEB_GetCurUpUserPortID();%>';
    var P2pFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_P2P);%>';
    var BJUNICOM = '<%HW_WEB_GetFeatureSupport(BBSP_FT_BJUNICOM);%>';
    var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
    var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
    var CurrUserMode = "";
    function stOpticInfo(domain, transOpticPower, revOpticPower) {
      this.domain = domain;
      this.transOpticPower = transOpticPower;
      this.revOpticPower = revOpticPower;
    }


    var opticInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic, TxPower|RxPower, stOpticInfo);%>;
    var opticInfo = opticInfos[0];

    function GEInfo(domain, Status) {
      this.domain = domain;
      this.Status = Status;
    }

    function stModifyUserInfo(domain, name) {
      this.domain = domain;
      this.name = name;
    }

    var geInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig, Link, GEInfo);%>;


    var superUserInfo = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2, UserName, stModifyUserInfo);%>;
    function isJLCU(page) {
      if ('JLCU' == CfgFtWord.toUpperCase()) {
        var styleState1 = page === 'home' ? 'none' : 'block';
        document.getElementById("regdeviceform").style.display = styleState1;
      }
      else {
        var styleState2 = page === 'home' ? 'block' : 'none';
        document.getElementById("regdeviceform").style.display = styleState2;
      }
    }
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

    function IsUsedCuHtml() {
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        return true;
      }

      return false;
    }

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
      }
      else if (((LoginTimes >= errloginlockNum) || (ModeCheckTimes >= errloginlockNum)) && parseInt(LockLeftTime) > 0) {
        var html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
        SetDivValue("DivErrPage", html);
        setDisable('txt_Password', 1);

        document.getElementById('adminphoto').onclick = function () { }

        document.getElementById('normalphoto').onclick = function () { }

        document.getElementById('regdevice').onclick = function () { }

        document.getElementById('btnSubmit').onclick = function () { }
        locklefttimerhandle = setInterval('showlefttime()', 1000);
      }
      else if (LoginTimes > 0 && LoginTimes < errloginlockNum) {
        if (('JSCU' == CfgFtWord.toUpperCase())) {
          SetDivValue("DivErrPage", "密码错误，请重新登录。");
        }
        else {
          SetDivValue("DivErrPage", "用户名或密码错误，请重新登录。");
        }
      }
      else {
        document.getElementById('loginfail').style.display = 'none';
      }

    }
    function SuperUserLogin() {
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        if (('JSCU' == CfgFtWord.toUpperCase())) {
          document.getElementById("btnsubmitform").style.display = "none";
          document.getElementById("regdeviceform").style.display = "block";
          document.getElementById("adminphoto").style.cursor = "default";
          document.getElementById("adminphoto").style.display = "block";
          CurrUserMode = "Admin";
          document.getElementById('adminphoto').onclick = function () { };
          document.getElementById('txt_Password').focus();
        }
        else {
          document.getElementById("btnsubmitform").style.display = "block";
          isJLCU();
        }

        document.getElementById("welcom").style.display = "none";
        document.getElementById("adminuser").style.display = "block";
        document.getElementById("normalphoto").style.display = "none";
        document.getElementById("adminphoto").style.marginLeft = "480px";
        document.getElementById("adminphoto").style.marginTop = "95px";
        document.getElementById("loginfail").style.display = "none";

        if (IsMaintWan == 1) {
          document.getElementById("adminuser").style.display = "none";
          document.getElementById("normaluser").style.display = "block";
        }
        CurrUserMode = "Admin";
      }
    }

    function SubmitForm() {
      var appName = navigator.appName;
      var version = navigator.appVersion;

      if (appName == "Microsoft Internet Explorer") {
        var versionNumber = version.split(" ")[3];
        if (parseInt(versionNumber.split(";")[0]) <= 6) {
          alert("不支持IE6.0及以下版本。");
          return false;
        }
      }

      if (CurrUserMode == "Admin") {
        var Username = "";
        if (IsMaintWan == 1) {
          Password = document.getElementById('txt_normalPassword');
        }
        else {
          Password = document.getElementById('txt_Password');
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
        if (IsMaintWan == 1) {
          Form.addParameter('UserName', document.getElementById('txt_normalUsername').value);
        }
        else {
          Form.addParameter('UserName', superUserInfo[0].name);
        }
        Form.addParameter('PassWord', base64encode(Password.value));
      }
      else if (CurrUserMode == "Normal") {
        var Username = document.getElementById('txt_normalUsername');
        var Password = document.getElementById('txt_normalPassword');

        if ('JSCU' == CfgFtWord.toUpperCase()) {
          Username.value = "user";
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
      }
      Form.addParameter('Language', Language);
      document.cookie = cookie2;
      Password.disabled = true;
      if (CurrUserMode == "Normal") {
        Username.disabled = true;
      }
      setCookie("MenuJumpIndex", "0");
      Form.addParameter('x.X_HW_Token', cnt);
      Form.setAction('/login.cgi');
      Form.submit();
      return true;
    }

    function canceltext() {
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
      regdevicebt();
      isJLCU('home');
      if ('JSCU' == CfgFtWord.toUpperCase()) {
        if (false == IsUsedCuHtml()) {
          ShowUser();
        }
        else {
          SuperUserLogin();
        }
      }
      else {
        document.getElementById("normalphoto").style.display = "block";
        ShowUser();
        SuperUserLogin();
      }

      document.getElementById('PwdPain').style.background = "url('/images/userinfo.gif')";
      document.getElementById('PwdPain1').style.background = "url('/images/userinfo.gif')";
      document.getElementById('AccountPain').style.background = "url('/images/usernum.gif')";
      clearInterval(locklefttimerhandle);
      var UserLeveladmin = '<%HW_WEB_CheckUserInfo();%>';

      if (CfgFtWord.toUpperCase() != 'UNICOMBRIDGE') {
        if (CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE' && CfgFtWordArea.toUpperCase() != '') {
          document.getElementById('ChooseInfo').innerHTML = CfgFtChineseArea;				//首页显示当前省份
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

      document.getElementById('txt_Password').focus();

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

      document.write('<div id="main_Lan" style="  margin-left: 98px; position: absolute; margin-top: 290px; font-family:Arial;font-size:12px;font-weight:bolder;"></div>');

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

    function AdminuserSubmit() {
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        return false;
      }
      window.location = "/CU.HTML";
      if (('JSCU' == CfgFtWord.toUpperCase())) {
        document.getElementById("btnsubmitform").style.display = "none";
        document.getElementById("regdeviceform").style.display = "block";
        return;
      }
      else {
        document.getElementById("btnsubmitform").style.display = "block";
        isJLCU();
      }
      document.getElementById("welcom").style.display = "none";
      document.getElementById("adminuser").style.display = "block";
      document.getElementById("normalphoto").style.display = "none";
      document.getElementById("adminphoto").style.marginLeft = "480px";
      document.getElementById("adminphoto").style.marginTop = "95px";
      document.getElementById("loginfail").style.display = "none";
      CurrUserMode = "Admin";
      document.getElementById('adminphoto').onclick = function () { };

      if (IsMaintWan == 1) {
        document.getElementById("adminuser").style.display = "none";
        document.getElementById("normaluser").style.display = "block";
      }
    }

    function AdminuserSubmit1() {
      if (('JSCU' == CfgFtWord.toUpperCase())) {
        return;
      }

      document.getElementById("btnsubmitform").style.display = "block";
      document.getElementById("welcom").style.display = "none";
      document.getElementById("normaluser").style.display = "block";
      document.getElementById("adminphoto").style.display = "none";
      document.getElementById("regdeviceform").style.display = "none";
      document.getElementById("normalphoto").style.marginLeft = "480px";
      document.getElementById("normalphoto").style.marginTop = "95px";
      document.getElementById("loginfail").style.display = "none";
      CurrUserMode = "Normal";
      document.getElementById('txt_normalUsername').focus();
    }
    function ShowUser() {
      if (BJUNICOM == "1") {
        document.getElementById("normalphoto").style.marginLeft = "480px";
        document.getElementById("normalphoto").style.display = "block";
        document.getElementById("welcom").style.display = "block";
        document.getElementById("regdeviceform").style.display = "none";
      }
      else if ('JSCU' == CfgFtWord.toUpperCase()) {
        document.getElementById("adminphoto").style.display = "none";
        document.getElementById("normalphoto").style.cursor = "default";
        document.getElementById("normalphoto").style.marginLeft = "480px";
        document.getElementById("normalphoto").style.display = "block";
        document.getElementById("welcom").style.display = "none";
        document.getElementById("regdeviceform").style.display = "none";
        document.getElementById("normaluser").style.display = "block";
        document.getElementById("AccountPain").style.display = "none";
        document.getElementById("normalphoto").style.display = "block";
        document.getElementById("normalphoto").src = "/images/normaluser_js.gif";
        document.getElementById('txt_normalPassword').focus();
        CurrUserMode = "Normal";
      }
      else {
        document.getElementById("adminphoto").style.display = "block";
        document.getElementById("normalphoto").style.display = "block";
        document.getElementById("welcom").style.display = "block";
      }
    }
    function regdevicebt() {
      var regdevlines = "";
      if (window.location.href.toUpperCase().indexOf("CU.HTML") > 0) {
        getRegStatus();
        var Infos = stResultInfos[0];
        if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)))) {
          if ('LNCU' == CfgFtWord.toUpperCase()) {
            regdevlines = '<img src="/images/regdevicebtn.gif" style="margin:50px 0 0 493px;width:83px;height:28px;cursor:pointer;" id="regdevice" name="regdevice" value="" />';
          }
          else {
            regdevlines = '<img src="/images/regdevicebtn.gif" style="margin:50px 0 0 493px;width:83px;height:28px;cursor:pointer;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>';
          }
        }
        else {
          regdevlines = '<img src="/images/regdevicebtn.gif" style="margin:50px 0 0 493px;width:83px;height:28px;cursor:pointer;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>';
        }
      }
      else {
        if (('BJCU' != CfgFtWord.toUpperCase()) && ('BJUNICOM' != CfgFtWord.toUpperCase())) {
          regdevlines = '<img src="/images/regdevicebtn.gif" style="margin:50px 0 0 493px;width:83px;height:28px;cursor:pointer;" id="regdevice" name="regdevice" value="" onClick="JumpToReg();"/>';
        }
      }
      document.getElementById("regdeviceform").innerHTML = regdevlines;
    }
    if (IsMaintWan == 1) {
      var starIdx = window.location.href.indexOf('://');
      var subAddr = window.location.href.substr(starIdx + 3);
      var newIp = subAddr.substring(0, subAddr.indexOf('/'));
      var http = 'http://' + newIp;
    }
    else {
      var http = 'http://' + br0Ip;
    }

  </script>
</head>

<body onLoad="LoadFrame();">
  <div id="main_wrapper"
    style="background-image:url(/images/background.gif);width:1066px;height:600px; background-repeat: no-repeat; margin: 0px auto;">
    <div style="width:100%;padding:75px 0 0 45px">
      <span id="ChooseInfo"
        style="font-weight:bolder;font-size:18px;font-family:Arial;color:#ff9800;text-align:center;">&nbsp</span>
    </div>

    <div style="width:100%;height:228px;">
      <img id="welcom" src="/images/welcom.gif" style="display:none" />
      <img id="adminphoto" src="/images/adminuser.gif" onclick="AdminuserSubmit();" />
      <img id="normalphoto" src="/images/normaluser.gif" onclick="AdminuserSubmit1();" style="display:none" />
    </div>

    <table id="adminuser" border="0" cellpadding="0" cellspacing="0" style="margin:15px 0 0 424px; display:none">
      <tr>
        <td id="PwdPain" style="width:220px;height:40px; background-repeat: no-repeat;">
          <div style="float:left;width:170px;">
            <input placeholder="●●●●●●●●●●●●●"
              style="color:#e2dede;font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin:10px 0 0 40px; width:120px;float:left"
              id="txt_Password" name="txt_Password" type="password" maxlength="127">
          </div>
          <div id="btnSubmit" style="width:40px;height:38px;cursor:pointer;float:left" onclick="SubmitForm();"> </div>
        </td>
      </tr>
    </table>

    <table id="normaluser" border="0" cellpadding="0" cellspacing="0"
      style="margin-left:424px; margin-top:15px; display:none">
      <tr>
        <td id="AccountPain" style="width:220px;height:40px; background-repeat: no-repeat;">
          <input placeholder="用户名"
            style="color:#e2dede;font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:40px; width:100px"
            id="txt_normalUsername" name="txt_Username" type="text" maxlength="32">
        </td>
      </tr>

      <tr>
        <td id="PwdPain1" style="width:220px;height:40px; background-repeat: no-repeat;">
          <div style="float:left;width:170px;">
            <input placeholder="●●●●●●●●●●●"
              style="color:#e2dede;font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin:10px 0 0 40px; width:100px"
              id="txt_normalPassword" name="txt_Password" type="password" maxlength="127">
          </div>
          <div style="width:40px;height:38px;cursor:pointer;float:left" onclick="SubmitForm();"> </div>
        </td>
      </tr>
    </table>

    <div id="btnsubmitform" style="display:none">

      <img style=" margin-left:505px; cursor:pointer;" src="/images/back1.gif"
        onclick="javascript:window.location.href=http" />

    </div>

    <div id="regdeviceform">


    </div>

    <div id="loginfail" style="display: none">
      <table border="0" cellpadding="0" cellspacing="15" height="33" width="100%">
        <tr>
          <td align="center" height="21" width="43%">

            <label id="DivErrPage" style="color:red;font-size:12px;font-family:Arial;"></label>

          </td>
        </tr>
      </table>
    </div>
  </div>
</body>

</html>