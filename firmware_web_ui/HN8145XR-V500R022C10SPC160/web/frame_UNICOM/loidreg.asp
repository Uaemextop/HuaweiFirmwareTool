<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    document.write('<title>中国联通</title>');
  </script>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta http-equiv="Pragma" content="no-cache" />
</head>

<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
<link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>" media="all" rel="stylesheet" />
<style type="text/css">
  .register-input {}

  .guangdong {
    width: 430px;
    font-size: 14px;
  }

  .qita {
    width: 400px;
  }

  .register-input tr {
    width: 100%;
  }

  .guangdong .register-input-title {
    width: 170px;

  }


  .guangdong .register-input-content {
    width: 260px;
  }

  .qita .register-input-title {
    width: 130px;
  }

  .qita .register-input-content {
    width: 270px;
  }

  .register-input-title {
    text-align: right;
  }

  .register-input-content .input {
    width: 150px;
    margin-left: 2em;
  }

  .input_time {
    border: 0px;
  }


  .submit_area {
    font: 12px Arial, ËÎÌå;
    color: #0000FF;
    height: 25px;
    width: 75px;
    margin-left: 2px;
    margin-bottom: 4px;
    padding-left: 0px;
    padding-right: 0px;

    background-color: #E1E1E1;
    display: inline-block;
  }

  .disabled {
    color: gray;
  }

  .goback {
    display: inline-block;
    padding-left: 4px;
    margin: 0px;
    height: 25px;
    color: #ff9800;
  }

  .progress {
    position: relative;
    left: 315px;
    top: 110px;
    background: url(../images/progress.gif);
    background-repeat: no-repeat;
    width: 438px;
    height: 27px;
  }

  .progress .progressbar {
    position: absolute;
    top: 7px;
    left: 6px;
    width: 0%;
    height: 15px;
    background-color: #ec6c00;
  }

  .progress-text {
    text-align: center;
    font-size: 15px;
  }
</style>

<style type="text/css">


</style>
<script type="text/javascript">

  function stResultInfo(domain, Result, Status) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
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
    new AreaRelationInfo("非RMS管理", "0000"),
    new AreaRelationInfo("RMS管理", "0001"),
    null);

    var sleep = function(time) {
      var startTime = new Date().getTime() + parseInt(time, 10);
      while(new Date().getTime() < startTime) {}
    };

  function GetE8CAreaByName(userEthInfos, name) {
    var length = userEthInfos.length;

    for (var i = 0; i < length - 1; i++) {
      if (name == userEthInfos[i].ChineseDes) {
        return userEthInfos[i].E8CArea;
      }
    }

    return null;
  }

  function GetE8CAreaByCfgFtWord(userEthInfos, name) {
    var length = userEthInfos.length;

    for (var i = 0; i < length - 1; i++) {
      if (name == userEthInfos[i].E8CArea) {
        return userEthInfos[i].ChineseDes;
      }
    }

    return null;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
  if (null != stResultInfos && null != stResultInfos[0]) {
    var Infos = stResultInfos[0];
  }
  else {
    var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
    var Infos = stResultInfos[0];
  }

  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
  var ProvinceArray = '<%GetChoiceProvinceInfo();%>';
  var IsWanAccess = '<%HW_WEB_IsWanAccess();%>';
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
  var LastChooseArea = '';
  var devicename = '<%GetAspPoductName();%>';
  var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
  var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
  var g_checkkey = "";
  if (IsWanAccess == 1) {
    if (window.location.href.indexOf('loidreg.asp') == -1) {
      if (window.location.href.charAt(window.location.href.length - 1) == '/') {
        window.location = window.location + 'loidreg.asp';
      }
      else {
        window.location = window.location + '/loidreg.asp';
      }
    }
  }
  else {
    if (IsMaintWan == 1) {
      var starIdx = window.location.href.indexOf('://');
      var subAddr = window.location.href.substr(starIdx + 3);
      var br0Ip = subAddr.substring(0, subAddr.indexOf('/'));
    }
    if (window.location.href.indexOf(br0Ip) == -1) {
      if (IsMaintWan != 1) {
        window.location = 'http://' + br0Ip + ':' + httpport + '/loidreg.asp';
      }
      else {
        window.location = 'http://' + br0Ip + '/loidreg.asp';
      }
    }
  }

  if ((parseInt(Infos.Result) == 1) && (0 == parseInt(Infos.Status))) {
    window.location = "/loidgregsuccess.asp";
  }

  var isSupportOptic = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_OPTIC);%>';
  var stbport = '<%HW_WEB_GetSTBPort();%>';
  var UpUserPortID = '<%HW_WEB_GetCurUpUserPortID();%>';
  var P2pFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_P2P);%>';

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

  var geInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig, Link, GEInfo);%>;

  function setRxPowerHtml() {
    if (0 != isSupportOptic) {
      if (opticInfo == null) {
        document.write('<div id="main_RxPower" style="  left: 100px; position: absolute; top: 240px; font-family:Arial;font-size:12px;">接收光功率：未知</div>');
        document.write('<div id="main_TxPower" style="  left: 100px; position: absolute; top: 260px; font-family:Arial;font-size:12px;">发送光功率：未知</div>');
      }
      else {
        document.write('<div id="main_RxPower" style="  left: 100px; position: absolute; top: 240px; font-family:Arial;font-size:12px;">接收光功率：' + opticInfo.revOpticPower + ' dBm</div>');
        document.write('<div id="main_TxPower" style="  left: 100px; position: absolute; top: 260px; font-family:Arial;font-size:12px;">发送光功率：' + opticInfo.transOpticPower + ' dBm</div>');
      }
    }

    document.write('<div id="main_Lan" style="  left: 98px; position: absolute; top: 280px; font-family:Arial;font-size:12px;"></div>');

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

  function Submit(type) {
    if (CheckForm(type) == true) {
      var Form = new webSubmitForm();
      AddSubmitParam(Form, type);
      Form.submit();
    }
  }

  function stDevInfo(domain, loid, eponpwd) {
    this.domain = domain;
    this.loid = loid;
    this.eponpwd = eponpwd;
  }

  function stOperateInfo(domain, Result, Status) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
  }

  var stDevInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, X_HW_Loid|X_HW_EponPwd, stDevInfo);%>;
  var stDevinfo = stDevInfos[0];

  var stOperateInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stOperateInfo);%>;
  if (null != stResultInfos && null != stResultInfos[0]) {
    var stOperateInfo = stOperateInfos[0];
  }
  else {
    var stOperateInfos = new Array(new stOperateInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
    var stOperateInfo = stOperateInfos[0];
  }

  function CheckForm() {
    var loid = getValue('LOIDValue');
    var eponpwd = getValue('PwdValue');
    var inLen = 0;

    if ((null == loid) || ('' == loid)) {
      alert("LOID不能为空，请输入正确的LOID。");
      return false;
    }

    if (!isValidAscii(loid)) {
      alert("LOID包含非ASCII字符，请输入正确的LOID。");
      return false;
    }

    if (loid.length > 24) {
      alert("LOID不能超过24个字符。");
      return false;
    }

    inLen = loid.length;
    if (inLen != 0) {
      if ((loid.charAt(0) == ' ') || (loid.charAt(inLen - 1) == ' ')) {
        if (false == confirm('您输入的LOID开始或结尾有空格，是否确认？')) {
          return false;
        }
      }
    }

    if ((null != eponpwd) && ('' != eponpwd)) {
      if (!isValidAscii(eponpwd)) {
        alert("PASSWORD包含非ASCII字符，请输入正确的PASSWORD。");
        return false;
      }

      if (eponpwd.length > 12) {
        alert("PASSWORD不能超过12个字符。");
        return false;
      }

      inLen = eponpwd.length;
      if (inLen != 0) {
        if ((eponpwd.charAt(0) == ' ') || (eponpwd.charAt(inLen - 1) == ' ')) {
          if (false == confirm('您输入的Password开始或结尾有空格，是否确认？')) {
            return false;
          }
        }
      }
    }

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
    if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
      var prop = window.innerWidth / 440;
      document.getElementById("background").style = "background-image:url(/images/backgroundforphone.gif); width:" + window.innerWidth + "px; height:" + window.innerHeight + "px; background-repeat: no-repeat; margin: 5px auto;"
      $('#background').css({"background-size":"cover", "position":"relative"});

      $('#regbutton').css({"display":"flex", "flex-direction":"column","margin-top":200 * prop + "px","width":"100%"});
      $('#PwdPain').css({"margin-top":20 * prop + "px","width":"100%"});
      $('#checkpwdtext').css({"display":"flex","margin-top":320 * prop + "px","width":"100%","font-size": 0.8 * prop + "rem"});

      $('#areanotice').css({"position":"absolute","bottom":240 * prop + "px","font-size":prop + "rem"});
      $('#RegInfomation').css({"position":"absolute","bottom":120 * prop + "px","font-size":0.8 * prop + "rem"});

      $('.submit_area').css({"width":100 * prop + "px","height":45 * prop + "px","margin-bottom":15 * prop + "px","font-size":1.5 * prop + "rem","text-align":"center"});
      $('#ChooseAreaModule').css({"heigh":"80%","width":"100%","font-size":prop + "rem"});
      $('#ChooseAreaModule1').css({"font-size":prop + "rem","margin":"50px","margin-top":100 * prop + "px","text-align": "center"});
      $('#backlogin').css({"position":"absolute","margin-right":10 * prop + "px","margin-top":20 * prop + "px","font-size": prop + "rem"});
      $('#selecttile').css({"text-align": "center","font-size":1.4 * prop + "rem"});

      $('#0000').css("font-size",prop + "rem");
      $('#0001').css("font-size",prop + "rem");
	  } else {
      document.getElementById("background").style = "background-image:url(/images/background.gif); width:1066px; height:1200px; background-repeat: no-repeat; margin: 0px auto;"
    }

    if ('GDCU' == CfgFtWord.toUpperCase()) {
      setDisable('PwdValue', 1);
    }

  }

  function AddSubmitParam1() {
    if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)))) {
      window.location = "/loidgregsuccess.asp";
      return;
    }

    if (CheckForm() == true) {
      var PrevTime = new Date();
      setCookie("lStartTime", PrevTime);
      setCookie("StepStatus", "0");
      setCookie("CheckOnline", "0");
      setCookie("lastPercent", "0");

      var SubmitForm = new webSubmitForm();

      SubmitForm.addParameter('x.UserName', getValue('LOIDValue'));
      SubmitForm.addParameter('x.UserId', getValue('PwdValue'));
      SubmitForm.addParameter('x.X_HW_Token', getAuthToken());
      SubmitForm.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=loidresult.asp');
      setDisable('btnApply', 1);
      setDisable('resetValue', 1);
      SubmitForm.submit();
    }
  }

  function AddSubmitParam2() {
    setText('LOIDValue', '');
    setText('PwdValue', '');
  }

  function CheckPwdCancel() {
    window.location.reload(true);
  }

</script>

<body onLoad="LoadFrame();">

  <div id="background">
    <div style="position:relative; top:50px; margin-left:785px; z-index:1999;">
      <script language="javascript">
        if (IsMaintWan == 1) {
          var starIdx = window.location.href.indexOf('://');
          var subAddr = window.location.href.substr(starIdx + 3);
          var br0Ip = subAddr.substring(0, subAddr.indexOf('/'));
        }

        if ("JSCU" == CfgFtWord.toUpperCase()) {
          document.write('<a href="http://' + br0Ip + "/CU.html" + '" style="font-size: 16px; text-decoration:none; color:#b2b2b2;"  id="backlogin" >返回登录页面</a>');
        }
        else {
          document.write('<a href="http://' + br0Ip + '" style="font-size: 16px; text-decoration:none; color:#b2b2b2;"  id="backlogin" >返回登录页面</a>');
        }
      </script>
    </div>

    <table cellSpacing="0" cellPadding="0" width="1066" style="font-size:14px;" align="center" border="0">
      <TBODY style="font-size:14px;">
        <TR>
          <table width="1066" height="417" border="0" align="center" cellpadding="0" cellspacing="0">
            <TBODY style="font-size:14px;">
              <TR>
                <TD id="registerground">
                  <div id="ChooseAreaModule"
                    style="font-family: '微软雅黑'; height:260px; width:1066px; display:none; font-size:14px;">
                    <div id="ChooseAreaModule1" style="margin:110px 320px 0 337px;text-align: left;">
                      <p style="text-align: center;">
                        <font id="selecttile" style="font-size: 16px; color: #b2b2b2;">&nbsp请选择所在地区:</font>
                      </p>
                      <input type="button" class="submit_area" name="010" id="010" value="北京" />
                      <input type="button" class="submit_area" name="021" id="021" value="上海" />
                      <input type="button" class="submit_area" name="022" id="022" value="天津" />
                      <input type="button" class="submit_area" name="023" id="023" value="重庆" />
                      <input type="button" class="submit_area" name="0551" id="0551" value="安徽" />
                      <input type="button" class="submit_area" name="0591" id="0591" value="福建" />
                      <input type="button" class="submit_area" name="0931" id="0931" value="甘肃" />
                      <input type="button" class="submit_area" name="020" id="020" value="广东" />
                      <input type="button" class="submit_area" name="0771" id="0771" value="广西" />
                      <input type="button" class="submit_area" name="0851" id="0851" value="贵州" />
                      <input type="button" class="submit_area" name="0898" id="0898" value="海南" />
                      <input type="button" class="submit_area" name="0311" id="0311" value="河北" />
                      <input type="button" class="submit_area" name="0371" id="0371" value="河南" />
                      <input type="button" class="submit_area" name="027" id="027" value="湖北" />
                      <input type="button" class="submit_area" name="0731" id="0731" value="湖南" />
                      <input type="button" class="submit_area" name="0431" id="0431" value="吉林" />
                      <input type="button" class="submit_area" name="025" id="025" value="江苏" />
                      <input type="button" class="submit_area" name="0791" id="0791" value="江西" />
                      <input type="button" class="submit_area" name="024" id="024" value="辽宁" />
                      <input type="button" class="submit_area" name="0951" id="0951" value="宁夏" />
                      <input type="button" class="submit_area" name="0971" id="0971" value="青海" />
                      <input type="button" class="submit_area" name="0531" id="0531" value="山东" />
                      <input type="button" class="submit_area" name="0351" id="0351" value="山西" />
                      <input type="button" class="submit_area" name="029" id="029" value="陕西" />
                      <input type="button" class="submit_area" name="028" id="028" value="四川" />
                      <input type="button" class="submit_area" name="0891" id="0891" value="西藏" />
                      <input type="button" class="submit_area" name="0991" id="0991" value="新疆" />
                      <input type="button" class="submit_area" name="0871" id="0871" value="云南" />
                      <input type="button" class="submit_area" name="0571" id="0571" value="浙江" />
                      <input type="button" class="submit_area" name="0451" id="0451" value="黑龙江" />
                      <input type="button" class="submit_area" name="0471" id="0471" value="内蒙古" />
                      <input type="button" class="submit_area" name="0000" id="0000" value="非RMS管理" />
                      <input type="button" class="submit_area" name="0001" id="0001" value="RMS管理" />
                    </div>
                  </div>

                  <div id="ApplyAreaModule" style="display:none;padding-top:40px">
                    <div class="progress">
                      <div class="progressbar"></div>
                    </div>

                    <p id="RedirectText" style="font-family: '微软雅黑'; text-align:center; height:90px"></p>
                    <div class="progress-text">0%</div>
                    <script type="text/javascript">
                      $('#ApplyAreaModule').children('table')
                        .addClass('register-input')
                    </script>
                  </div>

                  <div id="CheckPwdModule" style="margin:100px 0 0 340px;display:none;">
                    <div style="display:block; padding-left:83px;">
                      <h3 id="checkpwdtext" style="color:#e2dede;text-align: left;">请输入验证密码</h3>
                      <div id="PwdPain"
                        style="background-image:url(/images/userinfo.gif);width:220px;height:40px; background-repeat: no-repeat;">
                        <div style="float:left;width:170px;">
                          <input placeholder="●●●●●●●●●●"
                            style="color:#e2dede;font-size:16px;font-family:Tahoma,Arial; background:none; border:none;margin:9px 0 0 40px; width:120px;"
                            id="CheckPwdValue" name="CheckPwdValue" type="password" autocomplete="off" size="15"
                            maxlength="127" />
                        </div>
                        <div id="btnCheckPwdApply" class="submitApply"
                          style="width:45px;height:38px;cursor:pointer;float:left"> </div>
                      </div>
                    </div>
                    <font id="CheckPwdPrompt" style="font-family: '微软雅黑'; color:red;display:none;font-size: 14px;"
                      size="2">提示：输入的验证密码不正确，请找支撑经理从RMS平台获取。</font>
                  </div>

                  <div id="RegisterModule" class="" style="display:none;">

                    <div id="middlestyle" style="width:100%;height:100%">

                      <div id="regbutton" style="height:410px;">
                        <div style="padding:170px 0 0 0;">
                          <span>
                            <img id="loginlogo" style="width:107px;height:133px;" src="/images/idreg.gif" />
                          </span>
                        </div>

                        <div id="Regloidtitle" style="font-size:12px;color:red;">
                          <script language="javascript">
                            if ('GDCU' == CfgFtWord.toUpperCase()) {
                              document.write("注：终端该密码为空，不能填写");
                            }
                          </script>
                        </div>

                        <div style="padding:0 0 0 424px;">
                          <div id="AccountPain"
                            style="display:block; background-image:url(/images/usernum.gif);width:220px;height:40px; background-repeat: no-repeat;">
                            <input placeholder="逻辑ID"
                              style="color:#e2dede; font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin:10px 0 0 33px; width:155px"
                              id="LOIDValue" name="LOIDValue" type="text" maxlength="63">
                          </div>
                        </div>
                        <div style="padding:0 0 0 424px;">
                          <div id="PwdPain"
                            style="background-image:url(/images/regpassword.gif);width:220px;height:40px; background-repeat: no-repeat;">
                            <div style="float:left;width:168px;">
                              <input id="pwdinput" placeholder="密码"
                                style="color:#e2dede; font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin:11px 0 0 40px; width:110px"
                                id="PwdValue" name="PwdValue" type="text" maxlength="63">
                            </div>
                            <div id="inputbutton" style="width:50px;height:38px;cursor:pointer;float:left;" onclick="AddSubmitParam1();">
                            </div>
                          </div>
                        </div>
                      </div>

                      <div id="regnotice" style="margin-left:20px;float: left;text-align: left;">
                        <div id="areanotice" style="margin-left:20px;float: left;text-align: left;">
                          <span id="showChooseArea" style="font-family: '微软雅黑';color:#b2b2b2;">
                            <script language="javascript">

                              if ((CfgFtWord.toUpperCase() == 'UNICOM') || (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') || (CfgFtWord.toUpperCase() == 'UNICOMBRI')) {
                                if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                                  document.write("<font id='curArea'>当前配置为</font>");
                                } else {
                                  document.write("<font id='curArea' style='font-size: 12px;'>当前配置为</font>");
                                }
                              }
                              else {
                                if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                                  document.write("<font id='curArea'>当前配置地区为</font>");
                                } else {
                                  document.write("<font id='curArea' style='font-size: 12px;'>当前配置地区为</font>");
                                }
                              }
                            </script>
                            <font id="selecttext"><span id="SelectedArea"
                                style="color: #ff9800; font-weight: bold;"></span>，更改请<a href="#"
                                style="color: #ff9800; font-weight: bold;"
                                class="showChooseAreaModule">&nbsp点击&gt;&gt;</a></font>
                                <script language="javascript">
                                  if (!(navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                                    document.getElementById("selecttext").style = "font-size: 12px;";
                                  }
                                </script>
                          </span>
                        </div>
                        <span id="RegInfomation"
                          style="color:#b2b2b2; font-family: 微软雅黑;font-size:12px; text-align:left;">
                          <script language="javascript">
                            document.write('</br></br>' + devicename + '终端业务注册提示：</br>');
                            if (1 == IsLAN) {
                              document.write('1.请插紧上行连接线路</br>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔网线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册</br>网上营业厅 www.10010.com &nbsp&nbsp&nbsp客服热线 10010 &nbsp&nbsp&nbsp充值热线 10011');
                            }
                            else {
                              document.write('1.请插紧上行连接线路，检查并确认上行信号灯正常显示</br>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册');
                            }
                          </script>
                        </span>
                      </div>

                    </div>
                  </div>
              </TR>
            </TBODY>
          </table>
          </TD>
        </TR>
      </TBODY>
    </table>
  </div>
  <script type="text/javascript">
    $(document).ready(function () {
      var viewModel = {
        selectedArea: null,
        $ChooseAreaModule: $('#ChooseAreaModule'),
        $ChooseAreaModule1: $('#ChooseAreaModule1'),
        $ApplyAreaModule: $('#ApplyAreaModule'),
        $CheckPwdModule: $('#CheckPwdModule'),
        $RegisterModule: $('#RegisterModule')
      };


      viewModel.$ChooseAreaModule.delegate(':button', 'click', function () {

        var area = this.value;

        if (this.disabled) return false;

        viewModel.$ApplyAreaModule.trigger('start', area);

      }).bind({
        start: function (event, backable) {


          viewModel.$ApplyAreaModule.hide();
          viewModel.$RegisterModule.hide();

          viewModel.$ChooseAreaModule.show();

          var gobackBtn = viewModel.$ChooseAreaModule.find('.goback');

          if (backable === "noback") {

            gobackBtn.remove();

          } else {
            if (!gobackBtn.length) {
              if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                viewModel.$ChooseAreaModule1.append('<a class="goback" href="#" style="font-size: " + window.innerWidth / 440 + "rem;">返回&gt;&gt;</a>');
              } else {
                viewModel.$ChooseAreaModule1.append('<a class="goback" href="#" style="font-size: 14px;">返回&gt;&gt;</a>');
              }
            }
          }

          if (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') {
            ProvinceArray = '0001';
          }
          else {
            var temp = ProvinceArray;
            ProvinceArray = temp.replace('0001', 'ffff');
          }

          var enabledBtns = ProvinceArray;

          $('.submit_area').filter('[type="button"]').each(function (index) {
            var element = this;
            var name = element.name;
            if (enabledBtns.indexOf) {
              if (enabledBtns.indexOf(name) == -1) {
                $(this).attr('disabled', 'disabled').addClass('disabled');
              }
            } else {
              var included = false;
              $.each(enabledBtns, function (index, item) {
                if (item == name) {
                  included = true;
                  return false;
                }
              });

              if (!included) {
                $(element).attr('disabled', 'disabled').addClass('disabled');
              }
            }

          });

        }
      }).delegate('a.goback', 'click', function (event) {
        event.preventDefault();
        event.stopPropagation();

        viewModel.$RegisterModule.trigger('start');
      });

      viewModel.$ApplyAreaModule.bind({
        start: function (event, area) {
          var e8cArea;

          if (!area) {
            alert("您未选择任何区域!");
            return;
          }

          if ((parseInt(Infos.Result) == 1) && (0 == parseInt(Infos.Status))) {
            alert("已注册成功，请恢复出厂后重新选择所在地区！");
            return;
          }
          e8cArea = GetE8CAreaByName(userEthInfos, area);

          LastChooseArea = e8cArea;

          if ((e8cArea == '0000') && (CfgFtWord.toUpperCase() != 'UNICOMBRIDGE')) {
            tips = "您选择切换为非RMS管理方式，如果当前为RMS管理方式，可能导致业务不可用！该操作会自动重启设备，请确认是否执行？"
          }
          else if ((e8cArea == '0001') && (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE')) {
            tips = "您选择切换为RMS管理方式，如果当前为非RMS管理方式，可能导致业务不可用！请确认是否执行？"
          }
          else {
            tips = "您当前选择的地区为 【" + area + "】，是否确认?"
          }

          if (confirm(tips)) {

            viewModel.$ChooseAreaModule.hide();
            viewModel.$RegisterModule.hide();

            viewModel.$ApplyAreaModule.show();

            $.post('ConfigE8cArea.cgi?&RequestFile=loidreg.asp', { "AreaInfo": e8cArea, "CheckKey": g_checkkey, 'x.X_HW_Token': getAuthToken() });
            g_checkkey = "";

            window.CfgFtWordArea = e8cArea;
            sleep(1000);
            viewModel.$ApplyAreaModule.trigger('beginProgress');

          }
        },
        beginProgress: function () {
          var completeSeconds = 60;
          var startSeconds = 0;
          var startTime = new Date();
          var endTime = new Date();

          viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置，请勿断电...");
          viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));

          var interval = setInterval(function () {

            if (startSeconds != completeSeconds) {
              var configstatus = '';

              $.ajax({
                type: "POST",
                async: true,
                cache: false,
                url: "/asp/GetConfigStatusInfo.asp",
                success: function (data) {
                  configstatus = data;
                },
                error: function () {
                  configstatus = '';
                },

                complete: function () {
                  if (configstatus == '') {
                    if (parseInt((endTime.getTime() - startTime.getTime()) / 1000) > 40) {
                      viewModel.$ApplyAreaModule.find('#RedirectText').text("设备网络连接可能已断开，请检查你的网络连接状态。");
                    }
                  }
                  else if (configstatus == "DONE") {
                    viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置，请勿断电...");
                    startSeconds = completeSeconds;
                  }
                  else if (parseInt((startSeconds / completeSeconds) * 100) > 90) {
                    viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置，请勿断电...");
                    viewModel.$ApplyAreaModule.trigger('setProgress', 100);
                    startSeconds = completeSeconds;
                  }
                  else if (configstatus == "DOING") {
                    viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));
                    startSeconds += 1;
                  }

                  endTime = new Date();
                }


              });



            } else {

              viewModel.$ApplyAreaModule.trigger('setProgress', 100);

              viewModel.$ApplyAreaModule.trigger('endProgress');

              clearInterval(interval);
            };

          }, 1000);
        },
        setProgress: function (event, percent) {
          viewModel.$ApplyAreaModule.find('.progressbar').css('width', percent * 0.97 + '%');
          viewModel.$ApplyAreaModule.find('.progress-text').text(percent + '%');
        },
        endProgress: function () {

          redirectSeconds = 1;

          var tempInterval = setInterval(function () {

            if (redirectSeconds !== 0) {
              redirectSeconds -= 1;
            } else {
              clearInterval(tempInterval);
              if ((CfgFtWord.toUpperCase() != 'UNICOMBRIDGE') && (LastChooseArea == '0000')) {
                window.location.replace('/cu.html');
              }
              else {
                window.location.reload(true);
              }
            }
          }, 1000);

        }
      });
      viewModel.$CheckPwdModule.bind({
        start: function () {

          viewModel.$ChooseAreaModule.hide();
          viewModel.$ApplyAreaModule.hide();
          viewModel.$RegisterModule.hide();
          viewModel.$CheckPwdModule.show();
        }

      }).delegate('.submitApply', 'mousedown', function (event) {

        var CheckPassword = document.getElementById("CheckPwdValue").value;
        if (CheckPassword == '') {
          alert("输入的密码不能为空！");
          return false;
        }

        var CheckInfo = FormatUrlEncode(CheckPassword);
        var CheckResult = 0;
        g_checkkey = CheckPassword;

        $.ajax({
          type: "POST",
          async: false,
          cache: false,
          url: '/asp/CheckModifyInfo.asp?&1=1',
          data: 'CheckInfo=' + CheckInfo,
          success: function (data) {
            CheckResult = data;
          }
        });


        if (1 == CheckResult) {
          viewModel.$CheckPwdModule.hide();
          if (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') {
            viewModel.$ChooseAreaModule.trigger('start', 'noback');
          }
          else {
            viewModel.$ChooseAreaModule.trigger('start');
          }
        }
        else {

          document.getElementById('CheckPwdPrompt').style.display = "";
          viewModel.$CheckPwdModule.show();
        }


      });

      viewModel.$RegisterModule.bind({
        start: function () {
          viewModel.$ChooseAreaModule.hide();
          viewModel.$ApplyAreaModule.hide();
          viewModel.$RegisterModule.show();
          viewModel.$RegisterModule.find('#SelectedArea').text(GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea));

        }
      }).delegate('.showChooseAreaModule', 'click', function (event) {

        event.preventDefault();
        event.stopPropagation();

        if (CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE') {
          setText('CheckPwdValue', '');
          viewModel.$CheckPwdModule.trigger('start');
        }
        else {
          viewModel.$ChooseAreaModule.trigger('start');
        }
      });

      if (CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE') {
        viewModel.$RegisterModule.trigger('start');
      }
      else if (CfgFtWordArea.toUpperCase() == 'NOCHOOSE') {
        viewModel.$RegisterModule.trigger('start');
        document.getElementById('showChooseArea').style.display = "none";
      }
      else {
        if (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') {
          viewModel.$CheckPwdModule.show();
        }
        else {
          viewModel.$ChooseAreaModule.trigger('start', 'noback');
        }
      }
    });
  </script>
</body>

</html>