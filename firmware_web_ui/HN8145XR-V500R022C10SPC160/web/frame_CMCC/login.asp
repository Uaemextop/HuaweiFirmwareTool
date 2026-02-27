<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Cache-Control" content="no-cache">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <meta http-equiv="Expires" content="0">
  <title></title>
  <style type="text/css">
    #div_visite {
      margin-left: 50px;
      margin-top: 100px;
      margin-right: 50px;
      margin-bottom: 100px;
      font-family: "宋体";
      font-size: 12px;
      color: #333333;
    }

    .button_css {
      width: 80px;
      height: 36px;
      background: url(/images/button_cancel.gif);
      border-radius: 6px;
      border-width: 0;
      font-size: 15px;
      font-weight: bold;
      color: #5c5d55;
      cursor: pointer;
    }

    .button_css:hover {
      color: white;
      background: url(/images/button_confirm.gif);
    }


    table {
      font-family: "宋体";
      font-size: 15px;
    }
  </style>
  <link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>" media="all" rel="stylesheet" />
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <script language="JavaScript" type="text/javascript">
    var CMCCFTTO = '<%HW_WEB_GetFeatureSupport(FT_CMCC_FTTO);%>';

    function stResultInfo(domain, Result, Status) {
      this.domain = domain;
      this.Result = Result;
      this.Status = Status;
    }

    var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
    var Infos = stResultInfos[0];


    var FailStat = '<%HW_WEB_GetLoginFailStat();%>';
    var ModeCheckTimes = '<%HW_WEB_GetModPwdFailCnt();%>';
    var LoginTimes = <%HW_WEB_GetLoginFailCount();%>;
    var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
    var Language = "chinese";
    document.title = ProductName;
    var webRouteSet = '<%HW_WEB_GetFeatureSupport(BBSP_FT_ROUTE_BRIDGE_TRANSLATE);%>';
    var webHideLoidreg = '<%HW_WEB_GetFeatureSupport(FT_CMCC_HIDE_LOIDREG);%>';
    var LockLeftTime = '<%HW_WEB_GetLeftLockTime();%>';
    var errloginlockNum = '<%HW_WEB_GetTryLoginTimes();%>';
    var locklefttimerhandle;
    var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
    var APPVersion = '<%HW_WEB_GetAppVersion();%>';

    var DeviceType = '<%HW_WEB_GetDeviceType();%>';
    var IsSmartDev = "<%HW_WEB_GetFeatureSupport(FT_CMCC_RMS_OSGI);%>";
    var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';

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


    function SubmitForm() {
      var Username = document.getElementById('txt_Username');
      var Password = document.getElementById('txt_Password');
      var appName = navigator.appName;
      var version = navigator.appVersion;

      if (appName == "Microsoft Internet Explorer") {
        var versionNumber = version.split(" ")[3];
        if (parseInt(versionNumber.split(";")[0]) < 6) {
          alert("不支持IE6.0以下版本。");
          return;
        }
      }

      if (Username.value == "") {
        alert("用户名不能为空。");
        Username.focus();
        return false;
      }

      if (!isValidAscii(Username.value)) {
        alert("用户名包含非法字符.");
        Username.focus();
        return false;
      }

      if (Password.value == "") {
        alert("密码不能为空。");
        Password.focus();
        return false;
      }
      if (!isValidAscii(Password.value)) {
        alert("密码包含非法字符。");
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

      Form.addParameter('x.X_HW_Token', cnt);
      Form.setAction('/login.cgi');
      Form.submit();
      return true;
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

      document.getElementById('txt_Username').focus();

      if (1 == IsSmartDev) {
        var htmlDes = "<img src='/images/app.jpg' width='120' height='120' style='padding:15px 0 5px 0' />";
        htmlDes += "<p style='text-align:center; margin:0; padding-bottom:5px;'> APP </p> </td>";
        $("#appDiv").append(htmlDes);
      }


      if ((LoginTimes != null) && (LoginTimes != '') && (LoginTimes > 0)) {
        document.getElementById('loginfail').style.display = '';
      }

      if (("1" == FailStat) || (ModeCheckTimes >= errloginlockNum)) {
        document.getElementById('loginfail').style.display = '';
        setDisable('Submit2', 1);
        setDisable('btnSubmit', 1);
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);
        setDisable('regdevice', 1);
        if (webRouteSet == 1) {
          setDisable('routeSet', 1);
        }
      }

      init();

      if (LoginTimes >= errloginlockNum) {
        setDisable('Submit2', 1);
        setDisable('btnSubmit', 1);
        setDisable('txt_Username', 1);
        setDisable('txt_Password', 1);
        if (getElement('regdevice') != null) {
          setDisable('regdevice', 1);
        }

        if (webRouteSet == 1) {
          setDisable('routeSet', 1);
        }
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
      if (language == "chinese") {
        document.getElementById('Chinese').style.color = 'red';
        document.getElementById('English').style.color = 'black';
      } else {
        document.getElementById('Chinese').style.color = 'black';
        document.getElementById('English').style.color = 'red';
      }
    }

    function canceltext() {
      document.getElementById('txt_Username').value = "";
      document.getElementById('txt_Password').value = "";
    }

    function JumpToReg() {
      if (((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1))) {
        window.location = "/loidgregsuccess.asp";
      }
      else {
        window.location = "/loidreg.asp";
      }
    }

    function SetDivValue(Id, Value) {
      try {
        var Div = document.getElementById(Id);
        Div.innerHTML = Value;
      }
      catch (ex) {

      }
    }

    function showlefttime() {
      if (LockLeftTime <= 0) {
        window.location = "/login.asp";
        clearInterval(locklefttimerhandle);
        return;
      }

      var html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
      SetDivValue("loginfail", html);
      LockLeftTime = LockLeftTime - 1;
    }

  </script>
</head>

<body onload="LoadFrame();">
  <div id="div_visite">
    <div style="margin:50px 0 30px 0;">
      <img src="/images/cmcc_logo.gif" width="250" height="79" />
    </div>
    <div
      style="position:relative;width:420px;height:270px;border-radius:6px;margin:0 auto;background-color:#ececec;box-shadow:3px 5px 5px #c2c2c2;">
      <div
        style="position:absolute;top:15px;left:15px;width:390px;height:240px;background-color:#ffffff;border-radius:8px">
        <table>
          <tr style="position:absolute;top:55px;left:51px;">
            <td
              style="width:278px;height:38px;color:#5c5d55;font-size:15px;font-weight:bold;font-family:Arial;border:1px solid #dadada;background-color:#f4f8f9;">
              <span style="float:left;width:60px;height:38px;line-height:38px;text-align:center;">账号</span>
              <input name="txt_Username" type="text" id="txt_Username"
                style="float:left;padding:0;width:218px;height:38px;line-height:38px;text-indent:0.5em;border:0 solid green;background-color:transparent;"
                maxlength="32" />
            </td>
          </tr>

          <tr style="position:absolute;top:105px;left:51px;">
            <td
              style="width:278px;height:38px;color:#5c5d55;font-size:15px;font-weight:bold;font-family:Arial;border:1px solid #dadada;background-color:#f4f8f9;">
              <span style="float:left;width:60px;height:38px;line-height:38px;text-align:center;">密码</span>
              <input name="txt_Password" autocomplete="off" type="password" id="txt_Password" maxlength="127"
                style="float:left;padding:0;width:218px;height:38px;line-height:38px;text-indent:0.5em;border:0 solid green;background-color:transparent;"
                maxlength="31" />
            </td>
          </tr>

          <tr style="position:absolute;top:150px;left:45px;width:300px;font-size:12px;color:#FF0000;">
            <td style="width:300px;">
              <div id="loginfail" style="text-align: center;display:none;"></div>
              <script language="javascript">
                clearInterval(locklefttimerhandle);
                if ('1' == FailStat) {
                  SetDivValue("loginfail", "您登录失败的次数已超出限制。");
                }
                else if (LoginTimes > 0 && LoginTimes < errloginlockNum) {
                  SetDivValue("loginfail", "用户名或密码错误，请重新登录。");
                }
                else if (((LoginTimes >= errloginlockNum) || (ModeCheckTimes >= errloginlockNum)) && parseInt(LockLeftTime) > 0) {
                  var html = "";
                  if (LoginTimes >= errloginlockNum) {
                    html = '您登录失败的次数已超出限制，请' + LockLeftTime + '秒后重试！';
                  } else if (ModeCheckTimes >= errloginlockNum) {
                    html = '您尝试的次数已超出限制，请' + LockLeftTime + '秒后重试！';
                  }
                  SetDivValue("loginfail", html);
                  locklefttimerhandle = setInterval('showlefttime()', 1000);
                }
                else {
                  document.getElementById('loginfail').style.display = 'none';
                }
              </script>
            </td>
          </tr>

          <script language="javascript">
            if (1 == webHideLoidreg) {
              document.write('<tr style="position:absolute;top:170px;left:110px;">');
            }
            else {
              document.write('<tr style="position:absolute;top:170px;left:64px;">');
            }
          </script>
          <td>
            <input type="button" id="btnSubmit" name="btnSubmit" value="确定" onclick="SubmitForm();"
              class="button_css" />
            <input type="reset" name="Submit2" value="取消" onclick="canceltext();" class="button_css" />
            <script type="text/javascript" language="javascript">
              if ('HGU' == DeviceType.toUpperCase() && 1 != webHideLoidreg) {
                if (1 == IsMaintWan) {
                  document.write('<input type="button" name="regdevice" id="regdevice" hidden="hidden" class="button_css"');
                } else {
                  document.write('<input type="button" name="regdevice" id="regdevice" value="设备注册" onclick="JumpToReg()" class="button_css"');
                }
              }
            </script>
          </td>
          </tr>
        </table>
      </div>
    </div>
  </div>
  <script language="JavaScript" type="text/javascript">
  </script>
  <script language="JavaScript" type="text/javascript">
    if (CMCCFTTO == 0) {
      document.write('<div id="appDiv"></div>');
    }
  </script>

</body>

</html>