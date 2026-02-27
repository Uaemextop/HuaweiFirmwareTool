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

  #ChooseAreaModule .header {
    font-weight: bold;
    line-height: 18px;
    margin: 0px;
    padding: 0px;
    margin-bottom: 5px;
    text-align: center;
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
    color: red;
  }


  .content {
    width: 935px;
    height: 417px;
    position: absolute;
  }

  .content .prompt {
    position: absolute;
    top: 0px;
    left: 0px;
    width: 96%;
    height: 40px;
    ;
    border: 0px;
  }

  .content .module {
    position: absolute;
    top: 55px;
    left: 110px;
    width: 430px;
  }

  #SelectedArea {
    color: Red;
    font-weight: bold;
  }

  .progress {
    position: relative;
    left: 10px;
    background-color: white;
    width: 380px;
    height: 20px;
  }

  .progress .progressbar {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 0%;
    height: 18px;
    background-color: orange;
  }

  .progress .progress-text {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 378px;
    height: 16px;
    color: Black;
    text-align: center;
    font-size: 12px;
  }
</style>

<style type="text/css">
  div#RegisterModule {
    width: 935px;
    height: 417px;
    margin: 0px;
    padding: 0px;
    border-width: 0px;
    text-align: center;
    vertical-align: top;
    margin-left: auto;
    margin-right: auto;

    background-repeat: no-repeat 0px auto;
  }

  div#RegisterModule div#navhref {
    float: right;
    margin-top: 30px;
    margin-right: 30px;
  }

  div#RegisterModule div#middlestyle {
    clear: both;
  }

  div#RegisterModule div#regnotice {
    margin-left: 100px;
    margin-top: 40px;
    width: 350px;
    float: left;
  }

  div#RegisterModule div#regbutton {
    margin-right: 90px;
    margin-top: 30px;
    height: 210px;
    width: 325px;
    float: right;
  }
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

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo,Result|Status,stResultInfo);%>;
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
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
  var LastChooseArea = '';

  var devicename = '<%GetAspPoductName();%>';
  var zqcu = '<%HW_WEB_GetFeatureSupport(HW_FEATURE_ZQCU);%>';
  if (zqcu == 1) {
    devicename = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
  }
  var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';

  if (IsMaintWan == 1) {
    if (window.location.href.indexOf('loidreg.asp') == -1) {
      window.location = window.location.substr(0, window.location.href.lastIndexOf('/')) + '/loidreg.asp';
    }
  }
  else {
    if (window.location.href.indexOf(br0Ip) == -1) {
      window.location = 'http://' + br0Ip + ':' + httpport + '/loidreg.asp';
    }
  }

  if ((parseInt(Infos.Result) == 1) && (0 == parseInt(Infos.Status))) {
    window.location = "/loidgregsuccess.asp";
  }

  var isSupportOptic = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_OPTIC);%>';
  var stbport = '<%HW_WEB_GetSTBPort();%>';
  var UpUserPortID = '<%HW_WEB_GetCurUpUserPortID();%>';
  var P2pFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_P2P);%>';
  var g_checkkey = "";
  var HideArea = '<%HW_WEB_GetFeatureSupport(FT_SKIP_USERCHOICE_AREA);%>';
  function stOpticInfo(domain, transOpticPower, revOpticPower) {
    this.domain = domain;
    this.transOpticPower = transOpticPower;
    this.revOpticPower = revOpticPower;
  }

  var opticInfos = <% HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic, TxPower|RxPower, stOpticInfo);%>;
  var opticInfo = opticInfos[0];

  function GEInfo(domain, Status) {
    this.domain = domain;
    this.Status = Status;
  }

  var geInfos = <% HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig, Link, GEInfo);%>;

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
      var newForm = new webSubmitForm();
      AddSubmitParam(newForm, type);
      newForm.submit();
    }
  }

  function setCheckBoxValue(name) {
    var checkbox = getElement(name);
    if (checkBox.checked == true) {
      checkBox.value = 1;
    } else {
      checkBox.value = 0;
    }
  }

  function setRadioValue(name) {
    var radio = getElement(name);
    for (var i = 0; i < radio.length; i++) {
      if (radio[i].checked == false) {
        radio[i].disabled = true;
      }
    }
  }

  function MakeCheckBoxValue(srcForm) {
    var input = srcForm.getElementsByTagName("input");
    for (var i = 0; i < input.length; i++) {
      if (input[i].type == "checkbox") {
        setCheckBoxValue(input[i].name);
      } else if (input[i].type == "radio") {
        setRadioValue(input[i].name);
      }
    }
  }

  function debug(info) {
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

  var stDevInfos = <% HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, X_HW_Loid|X_HW_EponPwd, stDevInfo);%>;
  var stDevinfo = stDevInfos[0];

  var stOperateInfos = <% HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stOperateInfo);%>;
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

  function setCookie(name, value) {
    var expires = (setCookie.arguments.length > 2 ? setCookie.arguments[2] : null);
    var domain = (setCookie.arguments.length > 4 ? setCookie.arguments[4] : null);
    var secure = (setCookie.arguments.length > 5 ? setCookie.arguments[5] : false);

    var expiresStr = "";
    if (expires != null) {
      var expdate = new Date();
      expdate.setDate(expdate.getTime() + (expires * 1000));
      expiresStr = "expires=" + expdate.toGMTString() + ";";
    }
    document.cookie = name + "=" + escape(value) + ";" + expiresStr + "path=/;"
      + (domain == null ? "" : "domain=" + domain + ";")
      + (secure == true ? "secure" : "");
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
    if ('LNCU' == CfgFtWord.toUpperCase()) {
      document.getElementById('RegInfotitle').style.color = '#000000';
      document.getElementById('RegInfomation').style.color = '#000000';
      document.getElementById('Regloidtitle').style.color = '#000000';
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
  <form>
    <div align="center">
      <div style="position:relative; top:40px; margin-left:755px; z-index:1999;">
        <script language="javascript">
          if (IsMaintWan == 1) {
            var starIdx = window.location.href.indexOf('://');
            var subAddr = window.location.href.substr(starIdx + 3);
            var br0Ip = subAddr.substring(0, subAddr.indexOf('/'));
          }
          if (CfgFtWord.toUpperCase() == 'LNCU') {
            if (IsMaintWan != 1) {
              document.write('<A href="http://' + br0Ip + ':' + httpport + '/cu.html"><font style="font-size: 16px;" id="backlogin" color="#000000" style="font-weight:bold;">返回登录页面</FONT></A>');
            }
            else {
              document.write('<A href="http://' + br0Ip + '/cu.html"><font style="font-size: 16px;" id="backlogin" color="#000000" style="font-weight:bold;">返回登录页面</FONT></A>');
            }
          }
          else {
            if (IsMaintWan != 1) {
              document.write('<A href="http://' + br0Ip + ':' + httpport + '/cu.html"><font style="font-size: 16px;" id="backlogin" color="#3C1400" style="font-weight:bold;">返回登录页面</FONT></A>');
            }
            else {
              document.write('<A href="http://' + br0Ip + '/cu.html"><font style="font-size: 16px;" id="backlogin" color="#3C1400" style="font-weight:bold;">返回登录页面</FONT></A>');
            }
          }
        </script>
      </div>
      <table cellSpacing="0" cellPadding="0" width="935" style="font-size:14px;" align="center" border="0">
        <TBODY style="font-size:14px;">
          <TR>
            <TD>
              <table width="935" height="417" border="0" align="center" cellpadding="0" cellspacing="0">
                <TBODY style="font-size:14px;">
                  <TR>
                    <TD id="registerground" style="" align="center" width="935" height="417">

                      <div id="ChooseAreaModule" class="module" align="left"
                        style="font-family: '微软雅黑';display:none; width:420px; font-size:14px; height:260px;padding-top:0px">
                        <p class="header">
                          <font style="font-size: 14px;">请选择所在地区:</font>
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

                      <div id="ApplyAreaModule" class="module" style="display:none;padding-top:50px">

                        <div class="progress">
                          <div class="progressbar">
                            <div class="progress-text">0%</div>
                          </div>
                        </div>
                        <p id="RedirectText" style="font-family: '微软雅黑';text-align:center; height:220px"></p>

                        <script type="text/javascript">
                          $('#ApplyAreaModule').children('table')
                            .addClass('register-input')
                        </script>
                      </div>

                      <div id="CheckPwdModule" class="module" style="display:none;">
                        <p align="center">
                          <font style="font-family: '微软雅黑';font-size: 14px;">验证密码：</font><input type="password"
                            autocomplete="off" class="input" name="CheckPwdValue" id="CheckPwdValue" size="15"
                            style="font-size: 16px;" maxlength="127" /><strong style="color:#FF0033">*</strong>
                        </p>
                        <font id="CheckPwdPrompt"
                          style="font-family: '微软雅黑';margin-left:20px;display:none;font-size: 14px;" size="2">
                          提示：输入的验证密码不正确，请找支撑经理从RMS平台获取。</font>
                        <p style="text-align:center;">
                          <br>
                          <input style="width:75px; height:25px;font-size: 14px;" name="btnCheckPwdApply"
                            class="submitApply" id="btnCheckPwdApply" type="button" value="&nbsp;确&nbsp;认&nbsp;">
                          <input style="margin-left:45px;width:75px; height:25px;font-size: 14px;"
                            　name="btnCheckPwdCancel" class="submitCancel" id="btnCheckPwdCancel"
                            onClick="CheckPwdCancel();" type="button" value="&nbsp;取&nbsp;消&nbsp;">
                        </p>

                      </div>

                      <div id="RegisterModule" class="module" style="display:none; position:relative;">
                        <script language="javascript">
                          if (CfgFtWord.toUpperCase() == 'LNCU') {
                            document.write('<div id="main_hwlog" style="left: 400px; position: absolute; top: 0px; z-index: 1111; width: 100px;height: 80px;background-image:url(/images/logo.gif); background-repeat: no-repeat;"></div>');
                            document.write('<div id="main_underlogtxt" style="left: 478px; position: absolute;top: 42px; font-family:Arial;font-size:12px;font-weight:bolder;">设备型号：' + ProductName + '</div>');
                            setRxPowerHtml();
                          }
                        </script>
                        <div id="middlestyle">
                          <div id="regnotice">
                            <p>
                              <span style="font-family: '微软雅黑';font-size:20px;font-weight:bolder;color: #3c1400;"
                                id="username_txt">逻辑ID注册</span>
                            </p>
                            <p id="showChooseArea" colspan="2" style="font-family: '微软雅黑';text-align:center;">
                              <script language="javascript">
                                if ((CfgFtWord.toUpperCase() == 'UNICOM') || (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') || (CfgFtWord.toUpperCase() == 'UNICOMBRI')) {
                                  document.write("<font style='font-size: 14px;'>当前配置为</font>");
                                }
                                else {
                                  document.write("<font style='font-size: 14px;'>当前配置地区为</font>");
                                }
                              </script>
                              <font style='font-size: 14px;'><span id="SelectedArea"></span>，更改请<a href="#"
                                  class="showChooseAreaModule">点击&gt;&gt;</a></font>
                            </p>
                            <span id="RegInfotitle" style="color:#3C1400;font-family: 微软雅黑;font-size:14px">
                              <script language="javascript">
                                if ('LNCU' == CfgFtWord.toUpperCase()) {
                                  document.write("家庭网关终端逻辑ID注册提示：");
                                }
                                else {
                                  document.write(devicename + "终端业务注册提示：");
                                }
                              </script>
                            </span>
                            <p id="RegInfomation"
                              style="color:#3C1400;font-family: 微软雅黑;font-size:12px; text-align:left;">
                              <script language="javascript">
                                if (CfgFtWord.toUpperCase() == 'LNCU') {
                                  if (1 == IsLAN) {
                                    document.write('1.请插紧网线<br/>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔网线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册');
                                  }
                                  else {
                                    document.write('1.请插紧光纤，检查并确认LOS灯熄灭，PON灯闪烁</br>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册');
                                  }
                                }
                                else {
                                  if (1 == IsLAN) {
                                    document.write('1.请插紧上行连接线路</br>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔网线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册');
                                  }
                                  else {
                                    document.write('1.请插紧上行连接线路，检查并确认上行信号灯正常显示</br>2.准确输入“逻辑ID”和“密码”，点击“注册”进行注册</br>3.在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤线</br>4.本注册功能仅用于新设备的认证及业务下发，已正常在用设备请勿重新注册');
                                  }
                                }
                              </script>
                            </p>
                          </div>
                          <div id="regbutton">
                            <table width="100%" border="0" cellpadding="0" cellspacing="1">
                              <tr>
                                <td id="Regloidtitle" style="font-size:16px;font-weight:bold;color:#3C1400;">
                                  <script language="javascript">
                                    if ('GDCU' == CfgFtWord.toUpperCase()) {
                                      document.write("注：终端该密码为空，不能填写");
                                    }
                                    else {
                                      document.write("注：请您依次输入逻辑ID和密码");
                                    }
                                  </script>
                                </td>
                              </tr>
                              <tr>
                                <td style="height:10px;"></td>
                              </tr>
                              <tr>
                                <div
                                  style="position:relative; top:85px;margin-left:8px;height:20px; width:70px;font-family: '黑体';font-size:14px;font-weight:bolder;color:#414141;"
                                  id="username_txt">逻 辑 ID</div>
                                <td id="AccountPain"
                                  style="background-image:url(/images/userinfo.gif);width:242px;height:42px; background-repeat: no-repeat;">
                                  <input
                                    style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:-45px; width:100px"
                                    id="LOIDValue" name="LOIDValue" type="text" maxlength="63">
                                </td>
                              </tr>
                              <tr>
                                <td style="height:20px;"></td>
                              </tr>
                              <tr>
                                <div
                                  style="position:relative; top:125px;margin-left:14px;height:20px; width:70px;font-family: '黑体';font-size:14px;font-weight:bolder;color:#414141;"
                                  id="userpwd_txt">密 码</div>
                                <td id="PwdPain"
                                  style="background-image:url(/images/userinfo.gif);width:242px;height:42px; background-repeat: no-repeat;">
                                  <input
                                    style="font-size:14px;font-family:Tahoma,Arial; background:none; border:none;margin-left:-45px; width:100px"
                                    id="PwdValue" name="PwdValue" type="text" maxlength="63">
                                </td>
                              </tr>
                            </table>
                            <div style="position:relative;top:30px;left:-28px;">
                              <img src="/images/regbtn.gif" name="btnApply" class="submit" id="setReg"
                                onClick="AddSubmitParam1()" type="button" value="">
                              <img src="/images/resetbtn.gif" style="margin-left:45px;" name="resetValue"
                                id="resetValue" type="button" class="submit" onClick="AddSubmitParam2();" value="">
                            </div>
                          </div>
                        </div>
                      </div>
                  </TR>
                </TBODY>
              </TABLE>
            </TD>
          </TR>
        </TBODY>
      </TABLE>
    </div>

  </form>
  <script type="text/javascript">
    $(document).ready(function () {
      var viewModel = {
        selectedArea: null,
        $ChooseAreaModule: $('#ChooseAreaModule'),
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
              viewModel.$ChooseAreaModule.append('<a class="goback" href="#" style="font-size: 14px;">返回&gt;&gt;</a>');
              document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
            }
          }

          if (CfgFtWord.toUpperCase() == 'UNICOMBRIDGE') {
            ProvinceArray = '0001';
          }
          else {
            var temp = ProvinceArray;
            if(zqcu != 1) {
            ProvinceArray = temp.replace('0001', 'ffff');
          }
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
        if (CfgFtWord.toUpperCase() == 'LNCU') {
          document.getElementById('registerground').style.background = "url('/images/cu_register_cubg.jpg')";
        }
        else {
          document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
        }
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
            tips = "您当前选择的地区为" + area + "，是否确认?"
          }

          if (confirm(tips)) {

            viewModel.$ChooseAreaModule.hide();
            viewModel.$RegisterModule.hide();

            viewModel.$ApplyAreaModule.show();

            $.post('ConfigE8cArea.cgi?&RequestFile=loidreg.asp', { "AreaInfo": e8cArea, "CheckKey": g_checkkey, 'x.X_HW_Token': getAuthToken() });
            g_checkkey = "";

            window.CfgFtWordArea = e8cArea;

            viewModel.$ApplyAreaModule.trigger('beginProgress');

          }
        },
        beginProgress: function () {
          var completeSeconds = 50;
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
          viewModel.$ApplyAreaModule.find('.progressbar').css('width', percent + '%');
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

      }).delegate('.submitApply', 'click', function (event) {

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
        if (CfgFtWord.toUpperCase() == 'LNCU') {
          document.getElementById('registerground').style.background = "url('/images/cu_register_cubg.jpg')";
        }
        else {
          document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
        }

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

      if ((CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE') || ((zqcu == 1) && (HideArea == '1'))) {
        if (CfgFtWord.toUpperCase() == 'LNCU') {
          document.getElementById('registerground').style.background = "url('/images/cu_register_cubg.jpg')";
        }
        else {
          document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
        }

        viewModel.$RegisterModule.trigger('start');
      }
      else if (CfgFtWordArea.toUpperCase() == 'NOCHOOSE') {
        if (CfgFtWord.toUpperCase() == 'LNCU') {
          document.getElementById('registerground').style.background = "url('/images/cu_register_cubg.jpg')";
        }
        else {
          document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
        }

        viewModel.$RegisterModule.trigger('start');
        document.getElementById('showChooseArea').style.display = "none";
      }
      else {
        if (CfgFtWord.toUpperCase() == 'LNCU') {
          document.getElementById('registerground').style.background = "url('/images/cu_register_cubg.jpg')";
        }
        else {
          document.getElementById('registerground').style.background = "url('/images/register_cubg.gif')";
        }

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