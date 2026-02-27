<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    document.write('<title>中国移动</title>');
  </script>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta http-equiv="Pragma" content="no-cache" />
</head>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>

<style type="text/css">
  * {
    margin: 0;
    padding: 0;
  }

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

  .register-input-content .input {
    width: 150px;
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
    color: #ffffff;
    margin-bottom: 4px;
    padding-left: 0px;
    padding-right: 0px;
    background: url(/images/button_confirm.gif);
    display: inline-block;
    cursor: pointer;
    width: 80px;
    height: 35px;
    border-radius: 6px;
    border-width: 0;
    font-size: 14px;
    font-weight: bold;
  }

  .submit_area_phone {
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
    color: #5c5d55;
    background: url(/images/button_cancel.gif);
    cursor: default;
  }

  .disabled_phone {
    color: #5c5d55;
    cursor: default;
  }

  .goback {
    display: inline-block;
    padding-left: 4px;
    margin: 0px;
    height: 25px;
  }


  .content {
    width: 653px;
    height: 323px;
    position: absolute;
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
    background-color: #ededed;
    width: 600px;
    height: 20px;
  }

  .progress .progressbar {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 0%;
    height: 18px;
    background-color: #0081cc;
  }

  .progress .progress-text {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 600px;
    height: 16px;
    text-align: center;
    font-size: 12px;
  }

  .submitApply,
  .submitCancel,
  .submit {
    width: 80px;
    height: 35px;
    background: url(/images/button_cancel.gif);
    border-radius: 6px;
    border-width: 0;
    font-size: 15px;
    font-weight: bold;
    color: #5c5d55;
    cursor: pointer;
  }

  .submitApply:hover,
  .submitCancel:hover,
  .submit:hover {
    color: white;
    background: url(/images/button_confirm.gif);
  }
</style>
<script type="text/javascript">

  var JsCmccRms = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JSCMCC);%>';
  var ZJCmccRms = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_ZJCMCC_RMS);%>';
  var hideLoid = '<%HW_WEB_GetFeatureSupport(FT_CMCC_HIDE_LOIDREG);%>';
  var LoidPwdRmsReg = '<%HW_WEB_GetFeatureSupport(FT_RMS_REGISTER_LOID_PASSWORD);%>';
  var lefttime = 180 - '<%HW_WEB_GetRegLockLeftTime();%>';
  var LockCounter = null;

  if (hideLoid == 1) {
    window.location = "/";
  }

  function stResultInfo(domain, Result, Status, Limits, Times, X_HW_RmsRegType) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
    this.Limits = Limits;
    this.Times = Times;
    this.X_HW_RmsRegType = X_HW_RmsRegType;
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

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_RmsRegType, stResultInfo);%>;

  if (null != stResultInfos && null != stResultInfos[0]) {
    var Infos = stResultInfos[0];
  }
  else {
    var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99", "3", "0", "0"), null);
    var Infos = stResultInfos[0];
  }

  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';

  var CfgFtWordArea = '<%GetConfigAreaInfo();%>';

  var ProvinceArray = '<%GetChoiceProvinceInfo();%>';

  var CmccRegflag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CMCC_RMS);%>';
  var SavePwdLoid = '<%HW_WEB_GetFeatureSupport(FT_SAVE_PASSWORD_AND_LOID);%>';
  var X10Gpon = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_10GPON);%>';
  var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
  var IsCIOT = '<%HW_WEB_GetFeatureSupport(HW_OSGI_FT_CIOTMARK);%>';
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>';
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var LastChooseArea = '';
  var g_checkkey = "";

  var confirmWay = Infos.X_HW_RmsRegType;
  var var_regtype = Infos.X_HW_RmsRegType;
  var locklefttimerhandle;
  var isTimeout = false;
  var isPwdDisable = '<%WEB_GetRegCodeTimeoutStatus();%>';

  if (LoidPwdRmsReg == 0 && CmccRegflag == 1) {
    confirmWay = 1;
    var_regtype = 1;
  }

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
  if (null != stOperateInfos && null != stOperateInfos[0]) {
    var stOperateInfo = stOperateInfos[0];
  }
  else {
    var stResultInfos = new Array(new stOperateInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
    var stOperateInfo = stResultInfos[0];
  }

  function CheckLoidPswForm() {
    var loid = getValue('LOIDValue');
    var eponpwd = getValue('PwdValue');
    var inLen = 0;

    if ((null == loid) || ('' == loid)) {
      alert("LOID不能为空，请输入正确的LOID。");
      return false;
    }

    if (isValidAscii(loid) != '') {
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
      if (isValidAscii(eponpwd) != '') {
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

    if (CfgFtWordArea.toUpperCase() == 'CHOOSE') {
      if (getValue('SelectedAreaValue') == "") {
        alert("请选择地区。");
        return false;
      }
    }

    return true;
  }

  function CheckPswForm() {
    var eponpwd = getValue('PwdValue');

    if ((null == eponpwd) || ('' == eponpwd)) {
      alert("Password不能为空，请输入正确的Password。");
      return false;
    }


    if ((null != eponpwd) && ('' != eponpwd)) {
      if (isValidAscii(eponpwd) != '') {
        alert("Password包含非ASCII字符，请输入正确的Password。");
        return false;
      }

      if ((X10Gpon == 1) && (SavePwdLoid == 1)) {
        if (eponpwd.length > 24) {
          alert("Password不能超过24个字符。");
          return false;
        }
      } else {
        if (eponpwd.length > 10) {
          alert("Password不能超过10个字符。");
          return false;
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

  function setRmsDisabled(index) {
    var enabledBtns = ProvinceArray;
    var element = this;
    var name = element.name;
    if (enabledBtns.indexOf) {
      if (enabledBtns.indexOf(name) == -1) {
        if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
          $(this).attr('disabled', 'disabled').addClass('disabled_phone');
        } else {
          $(this).attr('disabled', 'disabled').addClass('disabled');
        }
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
        if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
          $(element).attr('disabled', 'disabled').addClass('disabled_phone');
        } else {
          $(element).attr('disabled', 'disabled').addClass('disabled');
        }
      }
    }
  }

  function LoadFrame() {
    if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
      var prop = window.innerWidth / 440;
      document.getElementById("background").style = "height:" + 0.8 * window.innerHeight + "px; width:100%; background-repeat: no-repeat; position:relative;"

      $('#inputnotice').css({"margin-top":180 * prop + "px","font-size":0.7 * prop + "rem"});
      $('#CheckPwdValue').css({"height":14 * prop + "px","width":80 * prop + "px","font-size":0.7 * prop + "rem"});

      $('#btnCheckPwdApply').css({"margin-top":20 * prop + "px","height":14 * prop + "px","width": 50 * prop + "px","font-size":0.6 * prop + "rem"});
      $('#btnCheckPwdCancel').css({"height":14 * prop + "px","width":50 * prop + "px","font-size":0.6 * prop + "rem"});
      $('#servicenotice1').css({"margin-top":30 * prop + "px","font-size":0.6 * prop + "rem","text-align":"center"});

      $('#backloginlink').css({"z-index":"2000","margin-top":15 * prop + "px","left":260 * prop + "px","font-size":0.5 * prop + "rem"});

      $('#ChooseAreaModule').css({"heigh":"80%","width":"100%","margin-left":-20 * prop + "px","margin-right":30 * prop + "px","margin-top":30 * prop + "px"});
      $('#choosetitle').css({"margin-left":50 * prop + "px","margin-top":30 * prop + "px","font-size":0.7 * prop + "rem"});
      $('#btnbackground').css({"heigh":window.innerHeight + "px","width":"125%","margin-top":30 * prop + "px"});
      $('#ChooseAreaModule input').removeClass("submit_area");
      $('#ChooseAreaModule input').addClass("submit_area_phone");
      $('#ChooseAreaModule input').css({"width":60 * prop + "px","height":45 * prop + "px","margin-right":5 * prop + "px","margin-bottom":10 * prop + "px","font-size":prop + "rem","text-align":"center"});

      $('#0451').css("font-size",0.8 * prop + "rem");
      $('#0471').css("font-size",0.8 * prop + "rem");
      $('#0000').css("font-size",0.6 * prop + "rem");
      $('#0001').css("font-size",0.6 * prop + "rem");
    }

    if (ZJCmccRms == 1) {
      setDisable('PwdValue', isPwdDisable);
      locklefttimerhandle = setInterval('CheckIsTimeout()', 1000);
    }
  }

  function CheckIsTimeout() {
    $.ajax({
      type: "POST",
      async: false,
      cache: false,
      url: '/asp/GetRegCodeTimerStatus.asp',
      success: function (data) {
        isTimeout = data;
      }
    });

    if (isTimeout == true) {
      setDisable('PwdValue', 1);
      clearInterval(locklefttimerhandle);
    }
  }

  function AddSubmitParam1() {
    if ((ZJCmccRms == 1) && (isTimeout == true)) {
      return;
    }

    if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1)))) {

      window.location = "/loidgregsuccess.asp";
      return;
    }

    if (CmccRegflag == 1) {
      if (1 == confirmWay) {
        if (CheckPswForm() == true) {
          var PrevTime = new Date();
          setCookie("lStartTime", PrevTime);
          setCookie("StepStatus", "0");
          setCookie("CheckOnline", "0");
          setCookie("lastPercent", "0");
          setCookie("GdTR069WanStatus", "0");
          setCookie("GdDispStatus", "0");
          setCookie("GdTR096WanIp", "0");

          var SubmitForm = new webSubmitForm();
          SubmitForm.addParameter('x.Password', getValue('PwdValue'));
          SubmitForm.addParameter('x.X_HW_RmsRegType', 1);
          SubmitForm.addParameter('x.X_HW_Token', getAuthToken());
          SubmitForm.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=loidresult.asp');
          setDisable('btnApply', 1);
          setDisable('resetValue', 1);
          SubmitForm.submit();
        }
      }
      else {
        if (CheckLoidPswForm() == true) {
          var PrevTime = new Date();
          setCookie("lStartTime", PrevTime);
          setCookie("StepStatus", "0");
          setCookie("CheckOnline", "0");
          setCookie("lastPercent", "0");
          setCookie("GdTR069WanStatus", "0");
          setCookie("GdDispStatus", "0");
          setCookie("GdTR096WanIp", "0");

          var SubmitForm = new webSubmitForm();
          SubmitForm.addParameter('x.UserName', getValue('LOIDValue'));
          SubmitForm.addParameter('x.UserId', getValue('PwdValue'));
          SubmitForm.addParameter('x.X_HW_RmsRegType', 0);
          SubmitForm.addParameter('x.X_HW_Token', getAuthToken());
          SubmitForm.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=loidresult.asp');
          setDisable('btnApply', 1);
          setDisable('resetValue', 1);
          SubmitForm.submit();
        }
      }
    }
    else {
      if (CheckLoidPswForm() == true) {
        var PrevTime = new Date();
        setCookie("lStartTime", PrevTime);
        setCookie("StepStatus", "0");
        setCookie("CheckOnline", "0");
        setCookie("lastPercent", "0");
        setCookie("GdTR069WanStatus", "0");
        setCookie("GdDispStatus", "0");
        setCookie("GdTR096WanIp", "0");

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
  }

  function AddSubmitParam2() {
    if (CmccRegflag == 0) {
      setText('LOIDValue', '');
    }
    setText('PwdValue', '');

    if (LoidPwdRmsReg == 1) {
      setText('LOIDValue', '');
      if (var_regtype == 1) {
        setRadio("rMethod", 2);
        document.getElementById('psw_prompt').style.display = "";
        document.getElementById('tr_pon_loid').style.display = "none";
        document.getElementById('ont_sn_des').innerHTML = "<h2>提示：</h2><h3>1、请插紧光纤并确认终端光信号已处于熄灭状态。</h3><h3>2、正确输入\"Password\"，点击\"确定\"进行注册。</h3><h3>3、在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤。</h3><h3>4、本注册功能仅用于新设备的认证及业务下发，已正常在用的设备请勿重新注册。</h3>";
        document.getElementById('passpwd_value').innerHTML = "Password：";

        confirmWay = 1;
      }
      else {
        setRadio("rMethod", 1);
        document.getElementById('tr_pon_loid').style.display = "";
        document.getElementById('psw_prompt').style.display = "none";
        document.getElementById('ont_sn_des').innerHTML = "<font style='font-size: 15px;'>请您输入申请业务时所提供的LOID和Password：</font>";
        document.getElementById('ont_loid_value').innerHTML = "<font style='font-size: 16px;'>LOID:</font>";
        document.getElementById('passpwd_value').innerHTML = "<font style='font-size: 16px;'>Password:</font>";

        confirmWay = 0;
      }
    }
  }

  function CheckPwdCancel() {
    window.location.reload(true);
  }

  function IsRegTimesToLimits() {
    return parseInt(Infos.Times) >= parseInt(Infos.Limits);
  }

  function onClickMethod() {
    setText('LOIDValue', '');
    setText('PwdValue', '');
    if (1 == getRadioVal("rMethod")) {
      document.getElementById('tr_pon_loid').style.display = "";
      document.getElementById('psw_prompt').style.display = "none";
      document.getElementById('ont_sn_des').innerHTML = "<font style='font-size: 15px;'>请您输入申请业务时所提供的LOID和Password：</font>";
      document.getElementById('ont_loid_value').innerHTML = "<font style='font-size: 16px;'>LOID:</font>";
      document.getElementById('passpwd_value').innerHTML = "<font style='font-size: 16px;'>Password:</font>";

      confirmWay = 0;
    }
    if ((2 == getRadioVal("rMethod"))) {
      document.getElementById('psw_prompt').style.display = "";
      document.getElementById('tr_pon_loid').style.display = "none";
      document.getElementById('ont_sn_des').innerHTML = "<h2>提示：</h2><h3>1、请插紧光纤并确认终端光信号已处于熄灭状态。</h3><h3>2、正确输入\"Password\"，点击\"确定\"进行注册。</h3><h3>3、在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤。</h3><h3>4、本注册功能仅用于新设备的认证及业务下发，已正常在用的设备请勿重新注册。</h3>";
      document.getElementById('passpwd_value').innerHTML = "Password：";

      confirmWay = 1;
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

  function IsFTCtrlAuthType() {
    if (CfgFtWordArea.toUpperCase() == '023') {
      return true;
    }
    return false;
  }

  function RegLockCounter() {
    if (lefttime > 0) {
      var html = '注册失败次数超出限制，请' + lefttime + '秒后重试。';
      SetDivValue("loidfail", html);
      lefttime--;
    }
    else {
      clearInterval(LockCounter);
      window.location = "/loidreg.asp";
    }
  }

</script>

<body onLoad="LoadFrame();">
  <form>

    <div align="center" style="position:relative;width:100%;height:80px;background-color:#efefef;">
      <img src="/images/cmccdevice_logo.gif" alt="" style="position:absolute;top:12px;left:323px;">
      <script language="javascript">
        document.write('<A id="backloginlink" href="http://' + br0Ip + ':' + httpport + '/login.asp" style="position:absolute;top:36px;left:1221px;width:120px;color:#0081cc;font-size:15px;font-weight:bold;text-decoration:none;">返回登录页面></A>');
      </script>
    </div>

    <div id="background" align="center">
      <table cellSpacing="0" cellPadding="0" width="653" align="center" border="0">
        <TR>
          <TD>
            <table width="653" height="400" border="0" align="center" cellpadding="0" cellspacing="0">
              <TR>
                <TD align="center" width="653" height="400">
                  <div id="ChooseAreaModule" class="module" align="left"
                    style="display:none;width:600px; height:400px;margin-top:40px;">
                    <p id="choosetitle" class="header"
                      style="padding-bottom:20px;height:60px;margin-bottom:33px;border-bottom:1px solid #f2f2f2;color:#0081cc;font-size:30px;line-height:60px;">
                      请选择所在地区:
                    </p>
                    <div id="btnbackground" style="width:444px;height:310px;margin:0 auto;">
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
                      <script language="javascript">
                        if (IsCIOT != 1) {
                          document.write('<input type="button"  class="submit_area" name="0000" id="0000" value="非RMS管理"/>');
                          document.write('<input type="button"  class="submit_area" name="0001" id="0001" value="RMS管理"/>');
                        }
                      </script>
                    </div>
                  </div>

                  <div id="ApplyAreaModule" class="module" style="display:none;padding-top:70px">

                    <div class="progress">
                      <div class="progressbar">
                        <div class="progress-text">0%</div>
                      </div>
                    </div>
                    <p id="RedirectText"
                      style="text-align:center; height:200px;font-size:15px;font-weight:bold;padding-top:15px;"></p>

                    <script type="text/javascript">
                      $('#ApplyAreaModule').children('table')
                        .addClass('register-input')
                    </script>
                  </div>

                  <div id="CheckPwdModule" class="module" style="display:none;">

                    <p id="inputnotice" align="center" style="font-weight:bold;">验证密码：
                      <input type="password" autocomplete="off" class="input" id="CheckPwdValue"
                        style="width:217px;height:38px;line-height:38px;text-indent:0.5em;border:1px solid #dadada;background-color:#ffffff;" />
                      <strong style="color:#FF0033;line-height:38px;">*</strong>
                    </p>
                    <p id="CheckPwdPrompt" style="display:none;padding-top:10px;font-size:15px;color:red;">
                      提示：输入的验证密码不正确，请找支撑经理从RMS平台获取。
                    </p>
                    <p style="text-align:center;padding-top:40px;">
                      <input name="btnCheckPwdApply" class="submitApply" id="btnCheckPwdApply" type="button" value="确认">
                      <input name="btnCheckPwdCancel" class="submitCancel" id="btnCheckPwdCancel"
                        onClick="CheckPwdCancel();" type="button" value="取消">
                    </p>

                    <script language="javascript">
                      if (ZJCmccRms != 1) {
                        document.write('<p id="servicenotice1" style="margin-top:18px;font-size:15px;font-weight:bold;text-align:center;color:#5c5d55;">中国移动客服热线10086号</p>');
                      }
                    </script>
                  </div>

                  <div id="RegisterModule" class="module" style="display:none;">
                    <TABLE cellSpacing="0" cellPadding="0" width="600" border="0" height="65%">
                      <tr id="showChooseArea">
                        <td colspan="2"
                          style="text-align:center;padding-top:10px;color:#5c5d55;font-size:15px;font-weight:bold;">
                          <script language="javascript">
                            if ((CfgFtWord.toUpperCase() == 'CMCC_RMS') || (CfgFtWord.toUpperCase() == 'CMCC_RMSBRIDGE')) {
                              document.write("<span style='color:#5c5d55;font-size:15px;font-weight:bold;'>当前配置为</span>");
                            }
                            else {
                              document.write("<span style='color:#5c5d55;font-size:15px;font-weight:bold;'>当前配置地区为</span>");
                            }
                          </script>
                          <span id="SelectedArea"></span>，更改请&nbsp<a href="#" class="showChooseAreaModule"
                            style="color:#0081cc;font-size:15px;text-decoration:none;font-weight:bold;">点击&gt;&gt;</a>
                        </td>
                      </tr>

                      <tr id="tr_pon_type" style="display:none;height:85px;">
                        <td colspan="2" height="18" align="left" id="pon_type" style="border-bottom:1px solid #f2f2f2;">
                        </td>
                      </tr>
                      <tr>
                        <td colspan="2" align="left" id="ont_sn_des"
                          style="padding:38px 0 30px 0;font-size:12px;line-height:25px;font-weight:bold;"></td>
                      </tr>
                      <tr>
                        <td colspan="2" align="center" id="otherinfo_des" style="padding-left:30px;"></td>
                      </tr>
                    </TABLE>


                    <div
                      style="position:relative;width:600px;height:205px;background-color:#f2f2f2;border-radius:10px;">
                      <table>
                        <script language="javascript">
                          if (LoidPwdRmsReg == 1) {
                            document.write('<tr id="TrSelectMethod">');
                            document.write('<td style="width:90px"><font style="font-size: 16px; font-weight: bold;">认证方式：</font></td>');
                            document.write('<td id="TrTdSelectMethod" >');
                            document.write('<div style="display:inline"><input name="rMethod" id="rMethod" type="radio" value="1" onclick="onClickMethod()"/>\
												LOID </div>');
                            document.write('<div style="display:inline; margin-left:60px;"><input name="rMethod" id="rMethod" type="radio"  value="2"  onclick="onClickMethod()" />\
												Password </div>');
                            document.write('</td>');

                            if (var_regtype == 1) {
                              setRadio("rMethod", 2);
                            }
                            else {
                              setRadio("rMethod", 1);
                            }

                            document.write('</tr>');
                          }
                        </script>

                        <tr id="tr_pon_loid"
                          style="display:none;position:absolute;top:28px;left:145px;font-weight:bold;">
                          <td class="register-input-title" id="ont_loid_value"
                            style="height:38px;width:83px;text-align:center;"></td>
                          <td class="register-input-content">
                            <input name="LOIDValue" class="input" id="LOIDValue" type="text"
                              style="width:217px;height:38px;line-height:38px;text-indent:0.5em;border:1px solid #dadada;background-color:#ffffff;">

                          </td>
                          <td>
                            <strong style="color:#FF0033;line-height:38px;">*</strong>
                          </td>
                        </tr>
                        <tr style="position:absolute;top:70px;left:145px;font-weight:bold;">
                          <td class="register-input-title" id="passpwd_value"
                            style="height:38px;text-align:center;width:83px;"></td>
                          <td class="register-input-content">
                            <input type="text" class="input" name="PwdValue" id="PwdValue"
                              style="width:217px;height:38px;line-height:38px;text-indent:0.5em;border:1px solid #dadada;background-color:#ffffff;" />
                          </td>
                          <td>
                            <strong id="psw_prompt" style="color:#FF0033;line-height:38px;">*</strong>
                          </td>
                        </tr>

                        <tr style="position:absolute;top:115px;left:145px;font-weight:bold;">
                          <td style="width:300px;" colSpan="2">
                            <div id="loidfail"
                              style="color:#FF0000;font-size:12px;font-weight:bold; text-align:center; display:none;">
                            </div>
                          </td>
                        </tr>

                        <script language="javascript">
                          document.getElementById('tr_pon_type').style.display = "";
                          document.write('<TR>');
                          if (1 == IsRhGateway) {
                            if (1 != IsLAN) {
                              if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>GPON上行融合智能终端</strong></p>";
                              }
                              else {
                                document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>EPON上行融合智能终端</strong></p>";
                              }
                            }
                            else {
                              document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>以太网上行融合智能终端</strong></p>";
                            }

                          }
                          else {
                            if (1 != IsLAN) {
                              if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>GPON上行终端</strong></p>";
                              }
                              else {
                                document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>EPON上行终端</strong></p>";
                              }
                            }
                            else {
                              document.getElementById('pon_type').innerHTML = "<p size='2' style='text-align:center;color:#0081cc;font-size:30px;'><strong>以太网上行智能终端</strong></p>";
                            }
                          }
                          document.write('</TR>');

                          if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
                            document.getElementById('psw_prompt').style.display = "";
                            if (1 != IsLAN) {
                              document.getElementById('ont_sn_des').innerHTML = "<h2>提示：</h2><h3>1、请插紧光纤并确认终端光信号已处于熄灭状态。</h3><h3>2、正确输入\"Password\"，点击\"确定\"进行注册。</h3><h3>3、在注册及业务下发过程中（10分钟内）不要断电、不要拔光纤。</h3><h3>4、本注册功能仅用于新设备的认证及业务下发，已正常在用的设备请勿重新注册。</h3>";
                            }
                            else {
                              document.getElementById('ont_sn_des').innerHTML = "<h2>提示：</h2><h3>1、请插紧网线。</h3><h3>2、正确输入\"Password\"，点击\"确定\"进行注册。</h3><h3>3、在注册及业务下发过程中（10分钟内）不要断电、不要拔网线。</h3><h3>4、本注册功能仅用于新设备的认证及业务下发，已正常在用的设备请勿重新注册。</h3>";
                            }
                            document.getElementById('passpwd_value').innerHTML = "Password：";
                          }
                          else {
                            document.getElementById('tr_pon_loid').style.display = "";
                            document.getElementById('psw_prompt').style.display = "none";
                            document.getElementById('ont_sn_des').innerHTML = "<font style='font-size: 15px;'>请您输入申请业务时所提供的LOID和Password：</font>";
                            document.getElementById('ont_loid_value').innerHTML = "<font style='font-size: 16px;'>LOID:</font>";
                            document.getElementById('passpwd_value').innerHTML = "<font style='font-size: 16px;'>Password:</font>";
                          }
                        </script>

                        <tr align="middle" colSpan="2" height="35"
                          style="position:absolute;top:145px;left:215px;text-align:left;">
                          <td>
                            <input name="btnApply" class="submit" id="setReg" onClick="AddSubmitParam1()" type="button"
                              value="确定" />
                          </td>
                          <td>
                            <input name="resetValue" id="resetValue" type="button" class="submit"
                              onClick="AddSubmitParam2();" value="重置" />
                          </td>
                        </tr>
                      </table>
                    </div>

                    <script language="javascript">
                      if (ZJCmccRms != 1) {
                        document.write('<span style="display:block;margin-top:18px;font-size:15px;font-weight:bold;color:#5c5d55;">中国移动客服热线10086号</span>');
                      }
                    </script>
                  </div>
                </TD>
              </TR>
            </TABLE>
          </TD>
        </TR>
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
              if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                var prop = window.innerWidth / 440;
                viewModel.$ChooseAreaModule.append('<a id="gobacklink" class="goback" href="#" style="color:#0081cc;font-size:40px;position:relative;bottom:-950px;left:400px">返回&gt;&gt;</a>');
              } else {
                viewModel.$ChooseAreaModule.append('<a id="gobacklink" class="goback" href="#" style="color:#0081cc;font-size:15px;position:relative;top:-62px;left:450px;">返回&gt;&gt;</a>');
              }
            }
          }
          if (CfgFtWord.toUpperCase() == 'CMCC_RMSBRIDGE') {
            ProvinceArray = '0001';
          }
          else {
            var temp = ProvinceArray;
            ProvinceArray = temp.replace('0001', 'ffff');
          }

          if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
            $('.submit_area_phone').filter('[type="button"]').each(setRmsDisabled);
          } else {
            $('.submit_area').filter('[type="button"]').each(setRmsDisabled);
          }
        }
      }).delegate('a.goback', 'click', function (event) {
        event.preventDefault();
        event.stopPropagation();

        viewModel.$RegisterModule.trigger('start');
      });


      viewModel.$ApplyAreaModule.bind({
        start: function (event, area) {
          var e8cArea;
          var tips;

          if (!area) {
            alert("您未选择任何区域!");
            return;
          }
          if (((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1))) {
            alert("已注册成功，请恢复出厂后重新选择所在地区！");
            return;
          }

          e8cArea = GetE8CAreaByName(userEthInfos, area);
          LastChooseArea = e8cArea;

          if ((e8cArea == '0000') && (CfgFtWord.toUpperCase() != 'CMCC_RMSBRIDGE')) {
            tips = "您选择切换为非RMS管理方式，如果当前为RMS管理方式，可能导致业务不可用！该操作会自动重启设备，请确认是否执行？"
          }
          else if ((e8cArea == '0001') && (CfgFtWord.toUpperCase() == 'CMCC_RMSBRIDGE')) {
            tips = "您选择切换为RMS管理方式，如果当前为非RMS管理方式，可能导致业务不可用！请确认是否执行？"
          }
          else {
            tips = "您当前选择的地区为 【" + area + "】，是否确认？"
          }

          if (confirm(tips)) {
            viewModel.$ChooseAreaModule.hide();
            viewModel.$RegisterModule.hide();

            viewModel.$ApplyAreaModule.show();


            $.post('ConfigE8cArea.cgi?&RequestFile=loidreg.asp', { "AreaInfo": e8cArea, "CheckKey": g_checkkey, 'x.X_HW_Token': getAuthToken() });


            window.CfgFtWordArea = e8cArea;



            viewModel.$ApplyAreaModule.trigger('beginProgress');

          }
        },
        beginProgress: function () {
          var completeSeconds = 50;
          var startSeconds = 0;
          var startTime = new Date();
          var endTime = new Date();

          if (IsFTCtrlAuthType() == true) {
            completeSeconds = 20;
          }

          viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置，请勿断电...");
          viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));

          var interval = setInterval(function () {
            if (startSeconds != completeSeconds) {
              var configstatus = '';

              if (startSeconds < 5) {
                viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));
                startSeconds++;
                return;
              }

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
                  if (IsFTCtrlAuthType() == true) {
                    if (configstatus == '') {
                      if (parseInt((endTime.getTime() - startTime.getTime()) / 1000) > 40) {
                        viewModel.$ApplyAreaModule.find('#RedirectText').text("设备网络连接可能已断开，请检查你的网络连接状态。");
                      }
                    }
                    else if (configstatus == "DONE" || configstatus == "CFGDATADONE") {
                      viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置，请勿断电...");
                      viewModel.$ApplyAreaModule.trigger('setProgress', 100);
                      startSeconds = completeSeconds;
                    }
                    else if (configstatus == "DOING") {
                      viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));
                      if (startSeconds < completeSeconds - 1) {
                        startSeconds += 1;
                      }
                    }
                  }
                  else {
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
                    else if (configstatus == "DOING" || configstatus == "CFGDATADONE") {
                      viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));
                      startSeconds += 1;
                    }
                  }
                  endTime = new Date();
                }
              });
            }
            else {
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
              if ((CfgFtWord.toUpperCase() != 'CMCC_RMSBRIDGE') && (LastChooseArea == '0000')) {
                window.location.replace('/login.asp');
              }
              else {
                if (IsFTCtrlAuthType() == true) {
                  setTimeout(
                    function () {
                      window.location.reload(true);
                    },
                    2000);
                }
                else {
                  window.location.reload(true);
                }
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

          if (CfgFtWord.toUpperCase() == 'CMCC_RMSBRIDGE') {
            viewModel.$ChooseAreaModule.trigger('start', 'noback');
          }
          else {
            viewModel.$ChooseAreaModule.trigger('start');
          }

          document.getElementById('CheckPwdPrompt').style.display = "none";
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
        if (CfgFtWord.toUpperCase() == 'CMCC_RMSBRIDGE') {
          viewModel.$CheckPwdModule.show();
        }
        else {
          viewModel.$ChooseAreaModule.trigger('start', 'noback');
        }
      }


    });

    if (JsCmccRms == 1) {
      if (IsRegTimesToLimits()) {
        setDisable('btnApply', 1);
        setDisable('resetValue', 1);
        setDisable('PwdValue', 1);
        var html = '注册失败次数超出限制，请' + lefttime + '秒后重试。';
        SetDivValue("loidfail", html);
        LockCounter = setInterval("RegLockCounter();", 1000);
        document.getElementById('loidfail').style.display = '';
      }
    }
  </script>
</body>

</html>