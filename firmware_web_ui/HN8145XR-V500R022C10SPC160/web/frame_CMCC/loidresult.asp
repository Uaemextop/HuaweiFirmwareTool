<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    var TelNum;
    document.write('<title>中国移动</title>');
    TelNum = '10086号';
  </script>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
</head>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<style>
  .input_time {
    border: 0px;
  }

  * {
    margin: 0;
    padding: 0;
  }
</style>

<script language="JavaScript" type="text/javascript">
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var CfgMode = '<%HW_WEB_GetCfgMode();%>';
  var ZJCmccRms = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_ZJCMCC_RMS);%>';
  var isCMCCOsgi = '<%HW_WEB_GetFeatureSupport(FT_CMCC_RMS_OSGI);%>';
  var isJSCMCC = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JSCMCC);%>';
  var isSmart = '<%HW_WEB_GetFeatureSupport(FT_CMCC_RMS_OSGI);%>';
  var cQcmcc = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CQCMCC);%>';

  var isJSCMCCSmart = false;
  if (isJSCMCC == '1' && isSmart == '1') {
    isJSCMCCSmart = true;
  }

  function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum, X_HW_RmsRegType) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
    this.Limits = Limits;
    this.Times = Times;
    this.RegTimerState = RegTimerState;
    this.InformStatus = InformStatus;
    this.ProvisioningCode = ProvisioningCode;
    this.ServiceNum = ServiceNum;
    this.X_HW_RmsRegType = X_HW_RmsRegType;
  }

  function WANIP(domain, ConnectionStatus, ExternalIPAddress, X_HW_SERVICELIST, ConnectionType, X_HW_TR069FLAG) {
    this.domain = domain;
    this.ConnectionStatus = ConnectionStatus;

    if (ConnectionType == 'IP_Bridged') {
      this.ExternalIPAddress = '';
    }
    else {
      this.ExternalIPAddress = ExternalIPAddress;
    }

    this.X_HW_SERVICELIST = X_HW_SERVICELIST;
    this.X_HW_TR069FLAG = X_HW_TR069FLAG;

  }

  function WANPPP(domain, ConnectionStatus, ExternalIPAddress, X_HW_SERVICELIST, ConnectionType, X_HW_TR069FLAG) {
    this.domain = domain;
    this.ConnectionStatus = ConnectionStatus;

    if (ConnectionType == 'PPPoE_Bridged') {
      this.ExternalIPAddress = '';
    }
    else {
      this.ExternalIPAddress = ExternalIPAddress;
    }
    this.X_HW_SERVICELIST = X_HW_SERVICELIST;
    this.X_HW_TR069FLAG = X_HW_TR069FLAG;
  }

  var opticInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic.RxPower);%>';
  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_TimeoutState|X_HW_InformStatus|ProvisioningCode|ServiceNum|X_HW_RmsRegType, stResultInfo);%>;
  var Infos = stResultInfos[0];
  var InfosBak = Infos;
  var ProvisionInfo = null;

  var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i}, ConnectionStatus||ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANIP);%>;
  var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}, ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANPPP);%>;
  var Wan = new Array();

  var stOnlineStatusInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>';
  var IsOntOnline = stOnlineStatusInfo;
  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
  var CmccRegflag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CMCC_RMS);%>';
  var loadedcolor = '#0081cc';
  var unloadedcolor = '#ededed';
  var bordercolor = '#ededed';
  var barheight = 15;
  var barwidth = 600;
  var ns4 = (document.layers) ? true : false;
  var ie4 = (document.all) ? true : false;
  var PBouter;
  var PBdone;
  var PBbckgnd;
  var txt = '';
  var acsUrl = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.ManagementServer.URL);%>';
  var GetLoidAuthStatus = '<%HW_WEB_GetLoidAuthStatus();%>';
  var opticMode = '<%HW_WEB_GetOpticMode();%>'
  var opticType = '<%HW_WEB_GetOpticType();%>';
  var GetCurrentRegPerCent = '<%HW_WEB_GetRegPerCent();%>';
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>';
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';

  var timer;
  var CheckDetailInfo = 1;
  var StartCheckStatus = 0;
  var RefreshCount = 0;
  var RefreshStop = 0;
  var isExistUserChoice = 1;
  var CurBinMode = '<%HW_WEB_GetBinMode();%>';
  var RefreshNum = 0;
  var CheckOnlineCnt = 0;
  var ResultTemp = '';
  var LoidPwdRmsReg = '<%HW_WEB_GetFeatureSupport(FT_RMS_REGISTER_LOID_PASSWORD);%>';
  var var_regtype = Infos.X_HW_RmsRegType;

  if (1 == IsLAN) {
    IsOntOnline = 1;
    GetLoidAuthStatus = 0;
  }

  function getLayerStr(isNs4, barheight, barwidth, bordercolor, barheight, unloadedcolor, loadedcolor) {
    var txt = '';
    if (isNs4) {
      txt += '<table border=0 cellpadding=0 cellspacing=0><tr><td>';
      txt += '<ilayer name="PBouter" visibility="hide" height="' + barheight + '" width="' + barwidth + '">';
      txt += '<layer width="' + barwidth + '" height="' + barheight + '" bgcolor="' + bordercolor + '" top="0" left="0"></layer>';
      txt += '<layer width="' + (barwidth - 2) + '" height="' + (barheight) + '" bgcolor="' + unloadedcolor + '"';
      txt += ' top="1" left="1"></layer>';
      txt += '<layer name="PBdone" width="' + (barwidth) + '" height="' + (barheight) + '"';
      txt += ' bgcolor="' + loadedcolor + '" top="1" left="1"></layer>';
      txt += '</ilayer>';
      txt += '</td></tr></table>';
    } else {
      txt += '<div id="PBouter" style="background-color:' + bordercolor + '; width:' + barwidth + 'px; height:' + barheight + 'px;';
      txt += ' position:relative; visibility:hidden;">';
      txt += '<div style="width:' + (barwidth) + 'px; height:' + (barheight) + 'px; background-color:' + unloadedcolor + ';';
      txt += ' position:absolute; top:1px; left:1px;font-size:1px;"></div>';
      txt += '<div id="PBdone" style="height:' + (barheight) + 'px; background-color:' + loadedcolor + ';';
      txt += ' position:absolute; top:1px; left:1px; width:0px;font-size:1px;"></div>';
      txt += '</div>';
    }
    return txt;
  }

  txt += getLayerStr(ns4, barheight, barwidth, bordercolor, barheight, unloadedcolor, loadedcolor);

  if ((parseInt(Infos.Result) == 1) && (parseInt(Infos.Status) == 0)) {
    window.location = "/loidgregsuccess.asp";
  }

  function LoidRegResultLog(RegResult) {
    if (ResultTemp != RegResult) {
      $.ajax({
        type: "POST",
        async: false,
        cache: false,
        url: "LoidRegResultLog.cgi?&RequestFile=loidgresult.asp",
        data: getDataWithToken('RegResult=' + RegResult),
        success: function (data) {
        }
      });

      ResultTemp = RegResult;
    }
  }

  function CheckWanInfo() {
    for (i = 0, j = 0; WanIp.length > 1 && j < WanIp.length - 1; i++, j++) {
      if ("1" == WanIp[j].X_HW_TR069FLAG) {
        i--;
        continue;
      }
      Wan[i] = WanIp[j];

      if ((Wan[i].ConnectionStatus == "Connected") && (-1 != Wan[i].X_HW_SERVICELIST.indexOf("TR069"))) {
        CheckDetailInfo = 0;
      }
    }

    for (j = 0; WanPpp.length > 1 && j < WanPpp.length - 1; i++, j++) {
      if ("1" == WanPpp[j].X_HW_TR069FLAG) {
        i--;
        continue;
      }
      Wan[i] = WanPpp[j];

      if ((Wan[i].ConnectionStatus == "Connected") && (-1 != Wan[i].X_HW_SERVICELIST.indexOf("TR069"))) {
        CheckDetailInfo = 0;
      }
    }
  }

  function resizeEl(id, t, r, b, l) {
    if (ns4) {
      id.clip.left = l;
      id.clip.top = t;
      id.clip.right = r;
      id.clip.bottom = b;
    }
    else {
      id.style.width = r + 'px';
    }
  }

  function FreshCountDel() {
    if (RefreshCount) {
      RefreshCount--;
    }

    RefreshStop = 0;
    RefreshNum = 0;
  }

  function LockNoticeForJSCMCC() {
    var bLOS = !IsOpticalNomal();
    //var limits = bLOS ? parseInt(Infos.Limits) : parseInt(Infos.Limits) - 1;
    var limits = parseInt(Infos.Limits);

    if ('JSCMCC_RMS' == CfgMode.toUpperCase()) {
      if (parseInt(Infos.Times) >= limits) {
        return "请3分钟后重试。";
      }
    }
    return "";
  }

  function GetProvisionServiceNameDesc(service) {
    if (service.toUpperCase() == "IPTV" || service.toUpperCase() == "ITV" || service.toUpperCase() == "OTT") {
      return (1 != isCMCCOsgi) ? "IPTV" : "组播类视频";
    }
    else if (service.toUpperCase() == "INTERNET") {
      return "上网";
    }
    else if (service.toUpperCase() == "VOICE" || service.toUpperCase() == "VOIP") {
      return "语音";
    }
    else if (service.toUpperCase() == "OTHER") {
      return "其它";
    }
  }

  function GetProvisionInfo() {
    var i;
    var Service;
    var Result;
    var Info = "";

    if (isJSCMCCSmart == false || ProvisionInfo == null) {
      return "";
    }

    for (i = 0; i < ProvisionInfo.Services.length; i++) {
      if (ProvisionInfo.Services[i] == null) {
        break;
      }
      Service = GetProvisionServiceNameDesc(ProvisionInfo.Services[i].ServiceName);
      Result = (ProvisionInfo.Services[i].Result == 1) ? "成功" : "失败";
      Info += Service + "业务下发" + Result + "，";
    }

    return Info;
  }
  function GetProvisionInfoSimple() {
    var i;
    var Service;
    var Info = [];

    if (isJSCMCCSmart == false || ProvisionInfo == null) {
      return "";
    }

    for (i = 0; i < ProvisionInfo.Services.length; i++) {
      if (ProvisionInfo.Services[i] == null) {
        break;
      }
      Service = GetProvisionServiceNameDesc(ProvisionInfo.Services[i].ServiceName);
      Info.push(Service);
    }

    return Info.toString().replace(/,/g, '、');
  }

  function myrefresh() {
    RefreshStop++;
    if (RefreshStop > 120) {
      return;
    }

    if (RefreshCount) {
      RefreshNum++;
      if (RefreshNum > 4) {
        RefreshCount = 0;
        RefreshNum = 0;
        LoadFrameInfo(2000);
        return;
      }

      if (((RefreshNum - 1) % 2) == 0) {
        LoadFrameInfo(1000);
      }
      else {
        setRefreshInterval(1000);
      }
      return;
    }

    RefreshCount++;
    $.ajax({
      type: "POST",
      async: true,
      cache: false,
      timeout: 4000,
      url: "/asp/GetOpticRxPower.asp",
      success: function (data) {
        opticInfo = hexDecode(data);
        FreshCountDel();
      }
    });

    RefreshCount++;
    $.ajax({
      type: "POST",
      async: true,
      cache: false,
      timeout: 4000,
      url: "asp/GetONTonlineStat.asp",
      success: function (data) {
        IsOntOnline = data;
        if (1 == IsLAN) {
          IsOntOnline = 1;
        }
        FreshCountDel();
      }
    });

    if (1 == IsOntOnline) {
      if (1 == CheckDetailInfo) {
        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegWanIp.asp",
          success: function (data) {
            WanIp = dealDataWithFun(data);
            FreshCountDel();
          }
        });

        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegWanPpp.asp",
          success: function (data) {
            WanPpp = dealDataWithFun(data);
            FreshCountDel();
          }
        });

        CheckWanInfo();
      }

      if ((1 < StartCheckStatus) && (0 == CheckDetailInfo)) {
        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegResult.asp",
          success: function (data) {
            Infos = dealDataWithFun(data);

            if (isJSCMCCSmart && (GetDateTimeDiff() <= 300)) {

              if (ProvisionInfo == null || ProvisionInfo.Status != 2) {
                Infos.Result = 0;
              }
              else {
                if (parseInt(Infos.Status) != parseInt(InfosBak.Status)) {
                  Infos.Result = InfosBak.Result;
                }
              }
            }
            else {
              if (parseInt(Infos.Status) != parseInt(InfosBak.Status)) {
                Infos.Result = InfosBak.Result;
              }
            }

            InfosBak = Infos;
            FreshCountDel();
          }
        });

        if (isJSCMCCSmart) {
          RefreshCount++;
          $.ajax({
            type: "POST",
            async: true,
            cache: false,
            timeout: 4000,
            url: "asp/GetProvisionResult.asp",
            success: function (data) {
              ProvisionInfo = $.parseJSON(hexDecode(data));

              FreshCountDel();
            }
          });
        }

        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegPerCent.asp",
          success: function (data) {
            GetCurrentRegPerCent = hexDecode(data);
            FreshCountDel();
          }
        });
      }
    }
    else {
      CheckDetailInfo = 1;
    }

    if (CheckDetailInfo) {
      RefreshCount++;
      $.ajax({
        type: "POST",
        async: true,
        cache: false,
        timeout: 4000,
        url: "asp/GetRegLoidAuthStatus.asp",
        success: function (data) {
          GetLoidAuthStatus = data;
          if (1 == IsLAN) {
            GetLoidAuthStatus = 0;
          }
          FreshCountDel();
        }
      });
    }

    LoadFrameInfo(2000);
  }

  function setPrograss(status, width) {
    PBouter = (ns4) ? findlayer('PBouter', document) : (ie4) ? document.all['PBouter'] : document.getElementById('PBouter');
    PBdone = (ns4) ? PBouter.document.layers['PBdone'] : (ie4) ? document.all['PBdone'] : document.getElementById('PBdone');
    if (ns4) {
      if (1 == status) {
        PBouter.visibility = "show";
      }
      else {
        PBouter.visibility = "hide";
      }
    }
    else {
      if (1 == status) {
        PBouter.style.visibility = "visible";
      }
      else {
        PBouter.style.visibility = "hidden";
      }
    }

    resizeEl(PBdone, 0, width, barheight - 2, 0);
  }

  function GetDateTimeDiff() {
    lStartTime = getCookie('lStartTime');
    if (lStartTime == null || lStartTime == "") {
      setCookie("lStartTime", new Date());
      return '1';
    }
    var CurrentTime = new Date();
    var PrevTime = new Date(getCookie("lStartTime"));
    return parseInt((CurrentTime.getTime() - PrevTime.getTime()) / 1000);
  }

  function GetStepStatus() {
    StepStatus = getCookie('StepStatus');
    if (StepStatus == null || StepStatus == "" || (StepStatus < '0' || StepStatus > '7')) {
      setCookie("StepStatus", "0");
      return '0';
    }
    return StepStatus;
  }


  function IsOpticPowerLow() {

    if (1 == IsLAN) {
      return false;
    }

    if (opticMode == 0) {
      if (opticType == 1) /* GPON */ {
        return opticInfo < -27;/* CLASS B+: (-27,-8) */
      }
      else if (opticType == 2) {
        return opticInfo < -30;/* CLASS C+: (-30,-8) */
      }
    }
    else if (opticMode == 1) /* EPON */ {
      if (opticType == 0) {
        return opticInfo < -24;/*PX20:  (-24,-3)*/
      }
      else if (opticType == 1) {
        return opticInfo < -27;/*PX20+: (-27,-3)*/
      }
    }
    return opticInfo < -27;
  }

  function GetAcsUrlAddress() {
    var aclUrlTmp1 = acsUrl.split('//');
    if (aclUrlTmp1.length > 1) {
      var aclUrlTmp2 = aclUrlTmp1[1].split(':');
      return (aclUrlTmp2[0]);
    }
    return aclUrlTmp1[0];
  }

  function StartRegStatus() {
    if (1 != IsLAN) {
      setPrograss(1, 120);
      document.getElementById('percent').innerHTML = "20%" + "（历时" + GetDateTimeDiff() + "秒）";
      if (IsOpticPowerLow()) {
        document.getElementById("regResult").innerHTML = "正在注册OLT。";
      }
      else {
        document.getElementById("regResult").innerHTML = "正在注册OLT。";
      }
    }
    else {
      setPrograss(1, 120);
      document.getElementById('percent').innerHTML = "30%" + "（历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "正在获取管理IP。";
    }
  }

  function setPrograss(status, width) {
    PBouter = (ns4) ? findlayer('PBouter', document) : (ie4) ? document.all['PBouter'] : document.getElementById('PBouter');
    PBdone = (ns4) ? PBouter.document.layers['PBdone'] : (ie4) ? document.all['PBdone'] : document.getElementById('PBdone');
    if (ns4) {
      if (1 == status) {
        PBouter.visibility = "show";
      }
      else {
        PBouter.visibility = "hide";
      }
    }
    else {
      if (1 == status) {
        PBouter.style.visibility = "visible";
      }
      else {
        PBouter.style.visibility = "hidden";
      }
    }

    resizeEl(PBdone, 0, width, barheight - 2, 0);
  }

  function setRefreshInterval(time) {

    timer = setTimeout('myrefresh()', time);

    return;
  }


  function IsOpticalNomal() {
    if (1 == IsLAN) {
      return true;
    }

    return opticInfo != "--";
  }


  function mystep() {
    if (1 != IsOntOnline) {
      CheckOnlineCnt = 0;
      setCookie("StepStatus", "3");
      return;
    }

    if (CheckOnlineCnt < 6) {
      CheckOnlineCnt++;
      return;
    }

    CheckOnlineCnt = 0;
    StartCheckStatus++;

    setPrograss(1, 180);
    document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
    document.getElementById("regResult").innerHTML = "正在获取管理IP。";

    setCookie("StepStatus", "2");
  }


  function setTipsBeforeITMSResult() {
    if ((!IsOpticalNomal()) || (1 == GetLoidAuthStatus && GetDateTimeDiff() > 40)) {
      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
        var htmlDes = (1 != IsLAN) ? "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、Password是否正确。" : "获取管理IP失败，请确认Password是否正确。";
        document.getElementById("regResult").innerHTML = htmlDes + LockNoticeForJSCMCC();
      }
      else {
        var htmlDes = (1 != IsLAN) ? "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、LOID和Password是否输入正确。" : "获取管理IP失败，请确认LOID和Password是否输入正确。";
        document.getElementById("regResult").innerHTML = htmlDes + LockNoticeForJSCMCC();
      }

      if (1 != IsLAN) {
        LoidRegResultLog("OLT_Fail");
      }

      setCookie("StepStatus", "4");
    }
    else if (GetStepStatus() == '0') {
      if (GetDateTimeDiff() > 300) {
        if (1 == IsLAN) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
            document.getElementById("regResult").innerHTML = "获取管理IP失败，请确认Password是否正确。";
          }
          else {
            document.getElementById("regResult").innerHTML = "获取管理IP失败，请确认LOID和Password是否输入正确。";
          }
          clearTimeout(timer);
          return;
        }

        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、Password是否正确。" + LockNoticeForJSCMCC();
        }
        else {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、LOID和Password是否输入正确。" + LockNoticeForJSCMCC();
        }
        LoidRegResultLog("OLT_Fail");
        clearTimeout(timer);
      }
      else {
        StartRegStatus();
        mystep();
      }
    }
    else if (GetStepStatus() == '2') {
      if (1 != IsOntOnline) {
        setCookie("StepStatus", "0");
      }
      StartCheckStatus++;

      if (GetDateTimeDiff() > 300) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        if (ZJCmccRms == 1) {
          var htmlDes = (1 != isCMCCOsgi) ? "到RMS的通道不通，请联系综合调度。" : "到省级数字家庭管理平台的通道不通，请联系综合调度。";
          document.getElementById("regResult").innerHTML = htmlDes;
        }
        else {
          var htmlDes = (1 != isCMCCOsgi) ? "到RMS的通道不通，请联系客户经理或拨打10086。" : "到省级数字家庭管理平台的通道不通，请联系客户经理或拨打10086。";
          document.getElementById("regResult").innerHTML = htmlDes + LockNoticeForJSCMCC();
        }
        LoidRegResultLog("RMS_NoIP");
      }
      else {
        setPrograss(1, 180);
        if (0 == Wan.length) {
          document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
          document.getElementById("regResult").innerHTML = "正在获取管理IP。";
        }
        else {
          for (i = 0; i < Wan.length; i++) {
            if (Wan[i].ConnectionStatus == "Connected" && ((Wan[i].X_HW_SERVICELIST == "TR069") || (Wan[i].X_HW_SERVICELIST == "TR069_VOIP") || (Wan[i].X_HW_SERVICELIST == "TR069_INTERNET") || (Wan[i].X_HW_SERVICELIST == "TR069_VOIP_INTERNET"))) {
              document.getElementById('percent').innerHTML = "40%" + " （历时" + GetDateTimeDiff() + "秒）";
              var htmlDes = (1 != isCMCCOsgi) ? "已获得管理IP，正在连接RMS。" : "已获得管理IP，正在连接省级数字家庭管理平台。";
              document.getElementById("regResult").innerHTML = htmlDes;
              setPrograss(1, 240);
              break;
            }
            else {
              document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
              document.getElementById("regResult").innerHTML = "正在获取管理IP。";
            }
          }
        }
      }
    }
    else if (GetStepStatus() == '3') {
      if (GetDateTimeDiff() > 300) {
        if (1 == IsLAN) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
            document.getElementById("regResult").innerHTML = "获取管理IP失败，请确认Password是否正确。";
          }
          else {
            document.getElementById("regResult").innerHTML = "获取管理IP失败，请确认LOID和Password是否输入正确。";
          }
          clearTimeout(timer);
          return;
        }

        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        if ((CmccRegflag == 1 && LoidPwdRmsReg == 0) || (LoidPwdRmsReg == 1 && var_regtype == 1)) {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、Password是否正确。" + LockNoticeForJSCMCC();
        }
        else {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、LOID和Password是否输入正确。" + LockNoticeForJSCMCC();
        }

        LoidRegResultLog("OLT_Fail");
        clearTimeout(timer);
      }
      else {
        StartRegStatus();
        CheckOnlineCnt = 0;
        setCookie("StepStatus", "0");
      }
    }
    else {

      if (GetStepStatus() == '4') {
        setCookie("lStartTime", new Date());
      }
      StartRegStatus();
      setCookie("StepStatus", "0");
    }
  }
  function getJSCMCCTips() {
    var htmlDes;
    var Results = GetProvisionInfo();
    var Count;
    var strNum;

    if (GetDateTimeDiff() > 300) {
      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      htmlDes = (1 != isCMCCOsgi) ? "RMS下发业务超时，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "省级数字家庭管理平台下发业务超时，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
    }
    else if (Results.indexOf("失败") >= 0) {
      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      htmlDes = (1 != isCMCCOsgi) ? "RMS下发业务异常，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "省级数字家庭管理平台下发业务异常，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
    }
    else {
      try {
        Count = ProvisionInfo.Services.length - 1;
      } catch (e) {
        Count = 0;
      }

      if (0 == Count) {
        strNum = "零";
      }
      else if (1 == Count) {
        strNum = "一";
      }
      else if (2 == Count) {
        strNum = "二";
      }
      else if (3 == Count) {
        strNum = "三";
      }
      else if (4 == Count) {
        strNum = "四";
      }
      else {
        strNum = "多";
      }

      htmlDes = (1 != isCMCCOsgi) ? "RMS平台业务数据下发成功，共下发了" + GetProvisionInfoSimple() + strNum + "个业务。" : "省级数字家庭管理平台业务数据下发成功，共下发了" + GetProvisionInfoSimple() + strNum + "个业务。";
    }
    return htmlDes;
  }
  function GetJSCMCCProgressPercent() {
    var Percent;
    var Base = 61;
    var Top = 99;
    var Step;
    var Count;

    if (ProvisionInfo == null) {
      return 60;
    }

    Step = (99 - 61) / ProvisionInfo.Total;
    Percent = Base;

    if (ProvisionInfo.Status == 2) {
      Percent = 99;
    }
    else if (ProvisionInfo.Status == 1) {
      if (ProvisionInfo.Total == 0) {
        Percent = 60;
      }
      else if (ProvisionInfo.Provisioned == 0) {
        Percent = Base;
      }
      else if (ProvisionInfo.Provisioned > 0 && ProvisionInfo.Current > 0) {
        if (ProvisionInfo.Services[ProvisionInfo.Current - 1].Status != 2
          && ProvisionInfo.Services[ProvisionInfo.Current - 1].FailCount == 0) {
          Count = ProvisionInfo.Provisioned - 1;
        }
        else {
          Count = ProvisionInfo.Provisioned;
        }

        Percent = Base + (Step * Count);
      }
    }


    return Math.round(Percent);
  }
  function GetJSCMCCProvisionCode() {
    var curIndex;
    if (ProvisionInfo == null) {
      return "";
    }

    curIndex = parseInt(ProvisionInfo.Current) - 1;

    if (curIndex >= 0 && curIndex < ProvisionInfo.Services.length - 1) {
      if (ProvisionInfo.Services[ProvisionInfo.Current - 1].Status != 2) {
        return ProvisionInfo.Services[ProvisionInfo.Current - 1].ServiceName;
      }
    }

    return "";
  }
  function getRegSuccessTips() {
    var strProvisioning = Infos.ProvisioningCode.split(',');
    var strNewProvisioning = '';
    var strNum;
    var htmlDes;
    LoidRegResultLog("RMS_CfgSuccess");
    for (i = 0; i < strProvisioning.length; i++) {
      if (strProvisioning[i].toUpperCase() == "IPTV" || strProvisioning[i].toUpperCase() == "ITV" || strProvisioning[i].toUpperCase() == "OTT") {
        strProvisioning[i] = (1 != isCMCCOsgi) ? "IPTV" : "组播类视频";
      }
      else if (strProvisioning[i].toUpperCase() == "INTERNET") {
        strProvisioning[i] = "上网";
      }
      else if (strProvisioning[i].toUpperCase() == "VOICE" || strProvisioning[i].toUpperCase() == "VOIP") {
        strProvisioning[i] = "语音";
      }
      else if (strProvisioning[i].toUpperCase() == "OTHER") {
        strProvisioning[i] = "其它";
      }
    }
    if ("" == Infos.ProvisioningCode) {
      if (isJSCMCCSmart) {
        return getJSCMCCTips();
      }
      else {
        return "注册成功，下发业务成功。";
      }
    }
    else {

      for (i = 0; i < strProvisioning.length - 1; i++) {
        strNewProvisioning = strNewProvisioning + strProvisioning[i] + '、';
      }
      strNewProvisioning = strNewProvisioning + strProvisioning[strProvisioning.length - 1];

      if (0 == strProvisioning.length) {
        strNum = "零";
      }
      else if (1 == strProvisioning.length) {
        strNum = "一";
      }
      else if (2 == strProvisioning.length) {
        strNum = "二";
      }
      else if (3 == strProvisioning.length) {
        strNum = "三";
      }
      else if (4 == strProvisioning.length) {
        strNum = "四";
      }
      else {
        strNum = "多";
      }

      if (isJSCMCCSmart) {
        htmlDes = getJSCMCCTips();
      }
      else {
        htmlDes = (1 != isCMCCOsgi) ? "RMS平台业务数据下发成功，共下发了" + strNewProvisioning + strNum + "个业务。" : "省级数字家庭管理平台业务数据下发成功，共下发了" + strNewProvisioning + strNum + "个业务。";
      }

      return htmlDes;
    }
  }

  function IsRegTimesToLimits() {
    return parseInt(Infos.Times) >= parseInt(Infos.Limits);
  }

  function ProvisionServicesSuccess() {
    setPrograss(1, 600);
    document.getElementById('percent').innerHTML = "100%";
    document.getElementById("regResult").innerHTML = getRegSuccessTips();
    clearTimeout(timer);
  }

  function LoadFrame() {
    CheckWanInfo();
    LoadFrameInfo(2000);
  }

  function LoadFrameInfo(time) {
    /* 启动超时定时器 */
    setRefreshInterval(time);

    if ((1 != IsOntOnline) || (0 != parseInt(Infos.InformStatus))) {
      Infos.Status = 99;
    }

    if (Infos != null) {
      if (parseInt(Infos.Status) == 0) {
        StartCheckStatus++;
        if (parseInt(Infos.Result) == 99) {
          setPrograss(1, 300);
          document.getElementById('percent').innerHTML = "50%" + "（历时" + GetDateTimeDiff() + "秒）";
          var htmlDes = (1 != isCMCCOsgi) ? "等待RMS平台下发业务数据。" : "等待省级数字家庭管理平台下发业务数据。";
          document.getElementById("regResult").innerHTML = htmlDes;

        }
        else if (parseInt(Infos.Result) == 0) {
          var strProvisioning;
          var percent;

          if (isJSCMCCSmart) {
            strProvisioning = [GetJSCMCCProgressPercent(), GetJSCMCCProvisionCode()];
          }
          else {
            strProvisioning = GetCurrentRegPerCent.split(',');
          }
          percent = parseInt(strProvisioning[0]);

          setPrograss(1, Math.round((percent * 297) / 50));

          if (("0" == Infos.ServiceNum) && ("" == Infos.ProvisioningCode) && (percent == 60)) {
            document.getElementById('percent').innerHTML = strProvisioning[0] + "%" + "（历时" + GetDateTimeDiff() + "秒）";

            var ponosgideshtml = "省级数字家庭管理平台正在下发业务数据，请勿断电或拔光纤。";
            var lanosgideshtml = "省级数字家庭管理平台正在下发业务数据，请勿断电或拔网线。";
            var pondeshtml = "RMS平台正在下发业务数据，请勿断电或拔光纤。";
            var landeshtml = "RMS平台正在下发业务数据，请勿断电或拔网线。";

            if (1 == IsLAN) {
              var htmlDes = (1 != isCMCCOsgi) ? landeshtml : lanosgideshtml;
            }
            else {
              var htmlDes = (1 != isCMCCOsgi) ? pondeshtml : ponosgideshtml;
            }

            document.getElementById("regResult").innerHTML = htmlDes;
          }
          else {
            var var_length = strProvisioning.length;
            var var_servername = strProvisioning[var_length - 1].toUpperCase();
            var strServiceName = "";

            if (var_servername == "IPTV" || var_servername == "ITV" || var_servername == "OTT") {
              strServiceName += (1 != isCMCCOsgi) ? "IPTV" : "组播类视频";;
            }
            else if (var_servername == "INTERNET") {
              strServiceName += "上网";
            }
            else if (var_servername == "VOICE" || var_servername == "VOIP") {
              strServiceName += "语音";
            }
            else if (var_servername == "OTHER") {
              strServiceName += "其它";
            }

            document.getElementById('percent').innerHTML = percent + "%" + "（历时" + GetDateTimeDiff() + "秒）";

            var ponosgideshtml = "省级数字家庭管理平台正在下发" + strServiceName + "业务数据，请勿断电或拔光纤。";
            var lanosgideshtml = "省级数字家庭管理平台正在下发" + strServiceName + "业务数据，请勿断电或拔网线。";
            var pondeshtml = "RMS平台正在下发" + strServiceName + "业务数据，请勿断电或拔光纤。";
            var landeshtml = "RMS平台正在下发" + strServiceName + "业务数据，请勿断电或拔网线。";

            if (1 == IsLAN) {
              var htmlDes = (1 != isCMCCOsgi) ? landeshtml : lanosgideshtml;
            }
            else {
              var htmlDes = (1 != isCMCCOsgi) ? pondeshtml : ponosgideshtml;
            }

            document.getElementById("regResult").innerHTML = htmlDes;
          }
        } else if (parseInt(Infos.Result) == 1) {
          if (cQcmcc == '1') {
            var serviceType = Infos.ProvisioningCode.split(',');
            if (parseInt(Infos.ServiceNum) <= serviceType.length) {
              ProvisionServicesSuccess();
            }
          } else {
            ProvisionServicesSuccess();
          }
        } else if (parseInt(Infos.Result) == 2) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          LoidRegResultLog("RMS_CfgFail");
          if (ZJCmccRms == 1) {
            var htmlDes1 = (1 != isCMCCOsgi) ? "RMS下发业务异常，请联系综合调度。" : "省级数字家庭管理平台下发业务异常，请联系综合调度。";
            document.getElementById("regResult").innerHTML = htmlDes1;
          } else {
            var htmlDes1 = (1 != isCMCCOsgi) ? "RMS下发业务异常，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "省级数字家庭管理平台下发业务异常，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
            document.getElementById("regResult").innerHTML = htmlDes1 + LockNoticeForJSCMCC();
          }

          clearTimeout(timer);
        }

        if (GetDateTimeDiff() > 600) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          var htmlDes = (1 != isCMCCOsgi) ? "等待RMS平台下发业务超时" : "等待省级数字家庭管理平台下发业务超时";
          document.getElementById("regResult").innerHTML = htmlDes + "（历时" + GetDateTimeDiff() + "秒）。";
          LoidRegResultLog("RMS_CfgTimeout");
          clearTimeout(timer);
        }
      }
      else if (parseInt(Infos.Status) == 1) {
        StartCheckStatus++;
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        LoidRegResultLog("RMS_RegFail");
        if (IsRegTimesToLimits()) {
          if (ZJCmccRms == 1) {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，请联系综合调度。" : "在省级数字家庭管理平台上注册失败，请联系综合调度。";
            document.getElementById("regResult").innerHTML = htmlDes1;
          }
          else {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "在省级数字家庭管理平台上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
            document.getElementById("regResult").innerHTML = htmlDes1 + LockNoticeForJSCMCC();
          }
        }
        else {
          var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，正在重试。" : "在省级数字家庭管理平台上注册失败，正在重试。";
          document.getElementById("regResult").innerHTML = htmlDes1;
        }
      }
      else if (parseInt(Infos.Status) == 2) {
        StartCheckStatus++;
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        LoidRegResultLog("RMS_RegFail");
        if (IsRegTimesToLimits()) {
          if (ZJCmccRms == 1) {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，请联系综合调度。" : "在省级数字家庭管理平台上注册失败，请联系综合调度。";
            document.getElementById("regResult").innerHTML = htmlDes1;
          }
          else {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "在省级数字家庭管理平台上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
            document.getElementById("regResult").innerHTML = htmlDes1 + LockNoticeForJSCMCC();
          }
        }
        else {
          var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，正在重试。" : "在省级数字家庭管理平台上注册失败，正在重试。";
          document.getElementById("regResult").innerHTML = htmlDes1;
        }
      }
      else if (parseInt(Infos.Status) == 3) {
        setPrograss(0, 0);
        LoidRegResultLog("RMS_RegFail");
        document.getElementById('percent').innerHTML = "";
        if (IsRegTimesToLimits()) {
          if (ZJCmccRms == 1) {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，请联系综合调度。" : "在省级数字家庭管理平台上注册失败，请联系综合调度。";
            document.getElementById("regResult").innerHTML = htmlDes1;
          }
          else {
            var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。" : "在省级数字家庭管理平台上注册失败，" + GetProvisionInfo() + "请联系客户经理或拨打10086。";
            document.getElementById("regResult").innerHTML = htmlDes1 + LockNoticeForJSCMCC();
          }
        }
        else {
          var htmlDes1 = (1 != isCMCCOsgi) ? "在RMS上注册失败，正在重试。" : "在省级数字家庭管理平台上注册失败，正在重试。";
          document.getElementById("regResult").innerHTML = htmlDes1;
        }
      }
      else if (parseInt(Infos.Status) == 4) {
        setPrograss(0, 0);
        LoidRegResultLog("RMS_Timeout");
        document.getElementById('percent').innerHTML = "";
        document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。" + LockNoticeForJSCMCC();
      }
      else if (parseInt(Infos.Status) == 5) {
        setPrograss(0, 0);
        LoidRegResultLog("RMS_RegRepeat");
        document.getElementById('percent').innerHTML = "";
        document.getElementById("regResult").innerHTML = "已经注册成功，无需再注册。";
      }
      else {
        setTipsBeforeITMSResult();
        return;
      }

    }
    else {
      setTipsBeforeITMSResult();
      return;
    }
  }

  function JumpTo() {
    clearTimeout(timer);

    if ((parseInt(Infos.Result) == 1) && (parseInt(Infos.Status) == 0)) {
      window.location = "/login.asp";
    }
    else {
      window.location = "/loidreg.asp";
    }
  }

</script>

<body onLoad="LoadFrame();">
  <form>
    <div align="center">
      <TABLE style="width:100%;height:80px;background-color:#efefef;">
        <TR>
          <TD style="position:relative;">
            <img src="/images/cmccdevice_logo.gif" alt="" style="position:absolute;top:15px;left:323px;">
            <script language="javascript">
              document.write('<a href="http://' + br0Ip + ':' + httpport + '/login.asp" style="position:absolute;top:36px;left:1221px;width:120px;color:#0081cc;font-size:15px;font-weight:bold;text-decoration:none;">返回登录页面></a>');
            </script>
          </TD>
        </TR>

        <TABLE>
          <script language="javascript">
            document.write('<TR>');
            if (1 == IsRhGateway) {
              if (1 != IsLAN) {
                if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                  document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>GPON上行融合智能终端</td>");
                }
                else {
                  document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>EPON上行融合智能终端</td>");
                }
              }
              else {
                document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>以太网上行融合智能终端</td>");
              }
            }
            else {
              if (1 != IsLAN) {
                if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                  document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>GPON上行终端</td>");
                }
                else {
                  document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>EPON上行终端</td>");
                }
              }
              else {
                document.write("<td style='padding-top:32px;padding-bottom:28px;width:600px;text-align:center;color:#0081cc;font-size:30px;font-weight:bold;border-bottom:1px solid #f2f2f2'>以太网上行智能终端</td>");
              }
            }
            document.write('</TR>');
          </script>
          <TR>
            <TD colspan="2" align="center">
              <div id="prograss" style="padding-top:30px;padding-bottom:15px;">
                <span id="percent" style="font-size:15px;font-weight:bold;color:#5c5d55;"></span>
              </div>
            </TD>
          </TR>
          <TR>
            <TD colspan="2" align="center">
              <script language="JavaScript" type="text/javascript">
                document.write(txt);
              </script>
            </TD>
          </TR>
          <TR height="8">
            <TD align="center" style="padding-top:15px;">
              <span id="regResult" style="font-size:15px;font-weight:bold;"></span>
            </TD>
          </TR>
          <TR>
            <TD align="center" style="padding-top:10px;">
              <input type="button" class="submit" value="返 回" onclick="JumpTo();"
                style="width:80px;height:35px;background:url(/images/button_cancel.gif);border-radius:6px;border-width:0;font-size:15px;font-weight:bold;color:#5c5d55;" />
            </TD>
          </TR>
          <TR>
            <script language="javascript">
              if (ZJCmccRms != 1) {
                document.write('<td style="padding-top:20px;font-size:15px;font-weight:bold;color:#5c5d55;text-align:center;">中国移动客服热线10086号</td>');
              }
            </script>
          </TR>
        </TABLE>
      </TABLE>
    </div>
  </form>
</body>

</html>