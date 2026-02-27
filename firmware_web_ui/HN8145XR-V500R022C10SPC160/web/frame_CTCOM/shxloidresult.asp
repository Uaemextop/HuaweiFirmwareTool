<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
</head>
<style>
  .input_time {
    border: 0px;
  }
</style>
<script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript">
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
  var simcardstatus = '<%webAspGetSimRegStatus();%>';
  var CfgMode = '<%HW_WEB_GetCfgMode();%>';
  var timer;
  function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum, Desc) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
    this.Limits = Limits;
    this.Times = Times;
    this.RegTimerState = RegTimerState;
    this.InformStatus = InformStatus;
    this.ProvisioningCode = ProvisioningCode;
    this.ServiceNum = ServiceNum;
    this.Desc = Desc;
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

  function PingResultClass(domain, FailureCount, SuccessCount) {
    this.domain = domain;
    this.FailureCount = FailureCount;
    this.SuccessCount = SuccessCount;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_TimeoutState|X_HW_InformStatus|ProvisioningCode|ServiceNum|Desc, stResultInfo);%>;
  if (null != stResultInfos && null != stResultInfos[0]) {
    var Infos = stResultInfos[0];
  }
  else {
    var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99", "10", "0", "NONE", "1", "", "", ""), null);
    var Infos = stResultInfos[0];
  }

  if (Infos.Status != 0 && Infos.Status != 97) {
    Infos.Status = 99;
    Infos.Result = 99;
  }
  var InfosBak = Infos;

  var opticInfo = -20;

  var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i}, ConnectionStatus||ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANIP);%>;
  var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}, ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANPPP);%>;
  var Wan = new Array();
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>'
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var PingResult = new PingResultClass("InternetGatewayDevice.IPPingDiagnostics", "0", "0");
  var stOnlineStatusInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>';
  var IsOntOnline = stOnlineStatusInfo;
  if (1 == IsLAN) {
    var IsOntOnline = 1;
  }

  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';

  var IsSupportVoice = '<%HW_WEB_GetFeatureSupport(HW_VSPA_FEATURE_VOIP);%>';

  var loadedcolor = 'orange';
  var unloadedcolor = 'white';
  var bordercolor = 'orange';
  var prograssheight = 15;
  var prograsswidth = 300;
  var ns4 = (document.layers) ? true : false;
  var ie4 = (document.all) ? true : false;
  var PBouter;
  var PBdone;
  var PBbckgnd;
  var htmltxt = '';
  var ResultTemp = '';

  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
  var MngtFjct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_FJCT);%>';
  var MngtScct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SCCT);%>';
  var MngtCqct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_CQCT);%>';
  var MngtSdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SDCT);%>';
  var MngtHljct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HLJCT);%>';
  var Mngtct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_CT);%>';
  var MngtHainct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HAINCT);%>';
  var MngtJsct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_JSCT);%>';
  var MngtSzct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SZCT);%>';
  var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';

  var RegPeriodFlag = '<%HW_WEB_GetRegPeriodFlag();%>';
  var acsUrl = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.ManagementServer.URL);%>';
  var GetCurrentRegPerCent = '<%HW_WEB_GetRegPerCent();%>';
  var RegPercents = [];
  var GetLoidAuthStatus = 0;
  var opticMode = '<%HW_WEB_GetOpticMode();%>'
  var opticType = '<%HW_WEB_GetOpticType();%>';
  var GetGDCTOpticAbnormal = 0;
  var CheckDetailInfo = 1;
  var StartPingFlag = 0;
  var StartCheckStatus = 0;
  var RefreshCount = 0;
  var RefreshStop = 0;
  var RefreshNum = 0;
  var isExistUserChoice = 1;
  var CheckCnt = 0;
  var CheckOnlineCnt = 0;
  var CurrentRegisterStep = GetWebCookie('RegisterStep');
  if (CurrentRegisterStep == null || CurrentRegisterStep == "") {
    setCookie("RegisterStep", "RPON");
    CurrentRegisterStep = "RPON";
  }

  RegPercents.push(GetCurrentRegPerCent);

  if (1 == MngtSdct) {
    Mngtct = 1;
  }

  function FromInnerLoidReg() {
    if (window.location.href.indexOf("ProgressPage=true") > 0) {
      return true;
    }
    return false
  }

  function LoidRegSuccess() {
    return (parseInt(Infos.Result) == 1) && ((parseInt(Infos.Status) == 0) || (1 == MngtGdct));
  }

  function LoidSaveNoProgress() {
    if (MngtJsct == '1' || MngtSzct == '1')
      return true;
    return false;
  }

  if (LoidSaveNoProgress() || (LoidRegSuccess() && !FromInnerLoidReg())) {
    window.location = "/loidgregsuccess.asp";
  }

  function CheckWanInfo() {
    for (i = 0, j = 0; WanIp.length > 1 && j < WanIp.length - 1; i++, j++) {
      if ("1" == WanIp[j].X_HW_TR069FLAG) {
        i--;
        continue;
      }
      Wan[i] = WanIp[j];

      if (Wan[i].ConnectionStatus == "Connected") {
        CheckDetailInfo = 0;
      }
    }

    for (j = 0; WanPpp.length > 1 && j < WanPpp.length - 1; i++, j++) {
      if ("1" == WanPpp[j].X_HW_TR069FLAG) {
        i--;
        continue;
      }
      Wan[i] = WanPpp[j];

      if (Wan[i].ConnectionStatus == "Connected") {
        CheckDetailInfo = 0;
      }
    }
  }

  if (ns4) {
    htmltxt += '<table border=0 cellpadding=0 cellspacing=0><tr><td>';
    htmltxt += '<ilayer name="PBouter" visibility="hide" height="' + prograssheight + '" width="' + prograsswidth + '">';
    htmltxt += '<layer width="' + prograsswidth + '" height="' + prograssheight + '" bgcolor="' + bordercolor + '" top="0" left="0"></layer>';
    htmltxt += '<layer width="' + (prograsswidth - 2) + '" height="' + (prograssheight - 2) + '" bgcolor="' + unloadedcolor + '" top="1" left="1"></layer>';
    htmltxt += '<layer name="PBdone" width="' + (prograsswidth - 2) + '" height="' + (prograssheight - 2) + '" bgcolor="' + loadedcolor + '" top="1" left="1"></layer>';
    htmltxt += '</ilayer></td></tr></table>';
  } else {
    htmltxt += '<div id="PBouter" style="position:relative; visibility:hidden; background-color:' + bordercolor + '; width:' + prograsswidth + 'px; height:' + prograssheight + 'px;">';
    htmltxt += '<div style="position:absolute; top:1px; left:1px; width:' + (prograsswidth - 2) + 'px; height:' + (prograssheight - 2) + 'px; background-color:' + unloadedcolor + '; font-size:1px;"></div>';
    htmltxt += '<div id="PBdone" style="position:absolute; top:1px; left:1px; width:0px; height:' + (prograssheight - 2) + 'px; background-color:' + loadedcolor + '; font-size:1px;"></div></div>';
  }

  function resizeinfo(id, top, right, bottom, left) {
    if (ns4) {
      id.clip.left = left;
      id.clip.top = top;
      id.clip.right = right;
      id.clip.bottom = bottom;
    } else {
      id.style.width = right + 'px';
    }
  }

  function FreshCountDel() {
    if (RefreshCount) {
      RefreshCount--;
    }

    RefreshStop = 0;
    RefreshNum = 0;
  }

  function CheckUserChoiceStatus() {
    var tmpFlag = 0;
    $.ajax({
      type: "POST",
      async: false,
      cache: false,
      timeout: 4000,
      url: "asp/GetUserChoiceStatus.asp",
      success: function (data) {
        tmpFlag = data;
      }
    });

    return tmpFlag;
  }

  function myrefresh() {
    if (1 == isExistUserChoice && CheckCnt < 40) {
      CheckCnt++;
      if (1 == CheckUserChoiceStatus()) {
        LoadFrameInfo(2000);
        return;
      }
      else {
        isExistUserChoice = 0;
      }
    }

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
      url: "asp/GetONTonlineStat.asp",
      success: function (data) {
        IsOntOnline = data;
        if (1 == IsLAN) {
          IsOntOnline = 1;
        }
        FreshCountDel();
      }
    });

    RefreshCount++;
    $.ajax({
      type: "POST",
      async: false,
      cache: false,
      timeout: 4000,
      url: "/asp/GetOpticRxPower.asp",
      success: function (data) {
        opticInfo = hexDecode(data);

        if (1 == MngtGdct) {
          GetGDCTOpticAbnormal = IsOpticPowerEorrorForGDCheck();
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

            try {
              Infos = dealDataWithFun(data);
              if (parseInt(Infos.Status) != parseInt(InfosBak.Status)) {
                Infos.Result = InfosBak.Result;
              }

              InfosBak = Infos;
              FreshCountDel();
            } catch (e) {
              ;
            }
          }
        });

        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegPerCent.asp",
          success: function (data) {
            try {
              GetCurrentRegPerCent = hexDecode(data);
              RegPercents.push(GetCurrentRegPerCent);
            } catch (e) {
              GetCurrentRegPerCent = data;
              RegPercents.push(GetCurrentRegPerCent);
            }
            FreshCountDel();
          }
        });
      }


      if (0 < StartPingFlag) {
        RefreshCount++;
        $.ajax({
          type: "POST",
          async: true,
          cache: false,
          timeout: 4000,
          url: "asp/GetRegPingResult.asp",
          success: function (data) {
            PingResult = dealDataWithFun(data);
            FreshCountDel();
          }
        });

        if (StartPingFlag < 4) {
          PingResult.FailureCount = 0;
          PingResult.SuccessCount = 0;
        }

        StartPingFlag++;
      }

      RefreshCount++;
      $.ajax({
        type: "POST",
        async: true,
        cache: false,
        timeout: 4000,
        url: "asp/GetRegPeriodFlag.asp",
        success: function (data) {
          RegPeriodFlag = data;
          FreshCountDel();
        }
      });

    }
    else {
      CheckDetailInfo = 1;
      StartCheckStatus = 0;
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
        if (1 == MngtSdct) {
          PBouter.visibility = "hide";
        }
        else {
          PBouter.visibility = "show";
        }
      }
      else {
        PBouter.visibility = "hide";
      }
    }
    else {
      if (1 == status) {
        if (1 == MngtSdct) {
          PBouter.style.visibility = "hidden";
        }
        else {
          PBouter.style.visibility = "visible";
        }
      }
      else {
        PBouter.style.visibility = "hidden";
      }
    }

    resizeinfo(PBdone, 0, width, prograssheight - 2, 0);
  }

  function GetWebCookie(name) {
    var cookiename = name + "=";
    var cookienamelen = cookiename.length;
    var cookielen = document.cookie.length;
    var i = 0;
    while (i < cookielen) {
      var j = i + cookienamelen;
      if (document.cookie.substring(i, j) == cookiename)
        return getCookieVal(j);
      i = document.cookie.indexOf(" ", i) + 1;
      if (i == 0) break;
    }
    return null;
  }

  function GetDateTimeDiff() {
    lStartTime = GetWebCookie('lStartTime');
    if (lStartTime == null || lStartTime == "") {
      setCookie("lStartTime", new Date());
      return '1';
    }
    var CurrentTime = new Date();
    var PrevTime = new Date(GetWebCookie("lStartTime"));
    return parseInt((CurrentTime.getTime() - PrevTime.getTime()) / 1000);
  }

  function GetStepStatus() {
    StepStatus = GetWebCookie('StepStatus');
    if (StepStatus == null || StepStatus == "" || (StepStatus < '0' || StepStatus > '7')) {
      setCookie("StepStatus", "0");
      return '0';
    }
    return StepStatus;
  }

  /**********************************
  GPON接收光功率范围：
  CLASS B+: (-27,-8)
  CLASS C+: (-30,-8)
  EPON接收光功率范围：
  PX20:  (-24,-3)
  PX20+: (-27,-3)
  其它:  参考PX20+的值。
  ***********************************/
  function IsOpticPowerLow() {

    if (ontPonMode.toUpperCase() == 'GPON') {
      if (opticType == 1) /* GPON */ {
        return opticInfo < -27;
      }
      else if (opticType == 2) {
        return opticInfo < -30;
      }
    }
    else if (ontPonMode.toUpperCase() == 'EPON') /* EPON */ {
      if (opticType == 0) {
        return opticInfo < -24;
      }
      else if (opticType == 1) {
        return opticInfo < -27;
      }
    }
    return opticInfo < -27;
  }



  /* 光功率不在合法范围则认为异常，正常的控制范围，GPON:(-31, -8)  EPON(-31, -3) */
  function IsOpticPowerEorrorForGDCheck() {
    if (ontPonMode.toUpperCase() == 'GPON') {
      if (parseInt(opticInfo) > -31 && parseInt(opticInfo) < -8) {
        return false;
      }

      return true;
    }
    else if (ontPonMode.toUpperCase() == 'EPON') /* EPON */ {
      if (parseInt(opticInfo) > -31 && parseInt(opticInfo) < -3) {
        return false;
      }

      return true;
    }

    return true;
  }

  function GetAcsUrlAddress() {
    var aclUrlTmp1 = acsUrl.split('//');
    if (aclUrlTmp1.length > 1) {
      var aclUrlTmp2 = aclUrlTmp1[1].split(':');
      return (aclUrlTmp2[0]);
    }
    return aclUrlTmp1[0];
  }

  function StartPingDiagnose() {
    var IPAddress = GetAcsUrlAddress();
    for (i = 0; i < Wan.length; i++) {
      if ((Wan[i].X_HW_SERVICELIST == "TR069") || (Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1)) {
        WanName = Wan[i].domain;
        break;
      }
    }

    var DSCP = 0;
    var PingData;
    StartPingFlag = 1;
    PingResult.SuccessCount = 0;
    PingResult.FailureCount = 0;

    PingData = "x.Host=" + IPAddress + "&x.DiagnosticsState=Requested" + "&x.NumberOfRepetitions=3" + "&x.DSCP=" + DSCP
    if (WanName != "") {
      PingData += "&x.Interface=" + WanName;
    }

    $.ajax({
      type: "POST",
      async: false,
      cache: false,
      data: getDataWithToken(PingData),
      url: "ping.cgi?x=InternetGatewayDevice.IPPingDiagnostics",
      success: function (data) {
        ;
      }
    });
  }

  function StartRegStatus() {
    if (1 == IsLAN) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + "（历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "正在获取管理IP。";
      return;
    }

    if (1 == Mngtct) {
      setPrograss(1, 60);
      document.getElementById('percent').innerHTML = "20%" + "（历时" + GetDateTimeDiff() + "秒）";
      if (IsOpticPowerLow()) {
        document.getElementById("regResult").innerHTML = "正在注册OLT" + "（光功率过低）。";
      }
      else {
        document.getElementById("regResult").innerHTML = "正在注册OLT。";
      }
    }
    else if (1 == MngtScct) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%";
      if (IsOpticPowerLow()) {
        document.getElementById("regResult").innerHTML = "终端正在注册OLT" + "（光功率过低）。";
      }
      else {
        document.getElementById("regResult").innerHTML = "终端正在注册OLT。";
      }
    }
    else if (1 == MngtGdct) {
      var prograssPercent = parseInt(1 + (22 * GetDateTimeDiff()) / (4 * 60));
      if (prograssPercent > 22) {
        prograssPercent = 22;
      }
      setPrograss(1, (prograssPercent * 297) / 100);
      document.getElementById('percent').innerHTML = prograssPercent + "%";
      document.getElementById("regResult").innerHTML = "终端正在向OLT注册，请等待；";
      setCookie("lastPercent", prograssPercent);
    }
    else {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + "（历时" + GetDateTimeDiff() + "秒）";
      if (IsOpticPowerLow()) {
        document.getElementById("regResult").innerHTML = "终端正在向OLT发起注册" + "（光功率过低）。";
      }
      else {
        document.getElementById("regResult").innerHTML = "终端正在向OLT发起注册。";
      }
    }
  }

  function setPrograss(status, width) {
    PBouter = (ns4) ? findlayer('PBouter', document) : (ie4) ? document.all['PBouter'] : document.getElementById('PBouter');
    PBdone = (ns4) ? PBouter.document.layers['PBdone'] : (ie4) ? document.all['PBdone'] : document.getElementById('PBdone');
    if (ns4) {
      if (1 == status) {
        if (1 == MngtSdct) {
          PBouter.visibility = "hide";
        }
        else {
          PBouter.visibility = "show";
        }
      }
      else {
        PBouter.visibility = "hide";
      }
    }
    else {
      if (1 == status) {
        if (1 == MngtSdct) {
          PBouter.style.visibility = "hidden";
        }
        else {
          PBouter.style.visibility = "visible";
        }
      }
      else {
        PBouter.style.visibility = "hidden";
      }
    }

    resizeinfo(PBdone, 0, width, prograssheight - 2, 0);
  }

  function setRefreshInterval(time) {

    timer = setTimeout('myrefresh()', time);

    return;
  }

  function IsOpticalNomal() {
    if (1 == IsLAN) {
      return true;
    }
    else {
      return opticInfo != "--";
    }

  }

  var itmsDesc = "TCMS";
  if (CfgMode.toUpperCase() == 'HUNCNCATV') {
      itmsDesc = "ITMS";
  }

  function mystepforLANDevice() {
    if (1 == Mngtct) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "正在获取管理IP。";
    }
    else if (1 == MngtScct) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%";
      document.getElementById("regResult").innerHTML = "终端正在获取管理地址。";
    }
    else if (1 == MngtGdct) {
      setPrograss(1, 75);
      document.getElementById('percent').innerHTML = "26%";
      document.getElementById("regResult").innerHTML = "终端正在获取管理地址，请等待。";
      setCookie("lastPercent", "26");
      setCookie("lStartTime", new Date());
    }
    else {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "终端正在向" + itmsDesc + "平台发起注册。";
    }
  }

  function mystep() {

    if (1 == IsLAN) {
      setPrograss(1, 90);
      mystepforLANDevice();
      StartCheckStatus++;
      setCookie("StepStatus", "2");
      return;
    }

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

    if (1 == Mngtct) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
      if (1 == MngtSdct) {
        document.getElementById("regResult").innerHTML = "注册OLT成功。";
      }
      else {
        document.getElementById("regResult").innerHTML = "注册OLT成功，正在获取管理IP。";
      }
    }
    else if (1 == MngtScct) {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%";
      document.getElementById("regResult").innerHTML = "终端注册OLT已成功，下一步将获取管理地址。";
    }
    else if (1 == MngtGdct) {
      setPrograss(1, 75);
      document.getElementById('percent').innerHTML = "25%";
      document.getElementById("regResult").innerHTML = "终端注册OLT成功；";
      setCookie("lastPercent", "25");
      setCookie("lStartTime", new Date());
    }
    else {
      setPrograss(1, 90);
      document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "终端在OLT已注册成功，下一步是终端向" + itmsDesc + "平台发起注册。";
    }

    setCookie("RegisterStep", "RWAN");
    setCookie("StepStatus", "2");
  }

  /* 非广东模式下，如果光功率异常或者LOID注册失败，则返回1，否则返回0 */
  /* 在判断LOID错误的时候延时20s是因为从后台获取输入的LOID认证结果需要一定时间，20s是一个经验值 */
  function CheckLoidFailForCT() {
    if (1 != IsLAN) {
      return ((!IsOpticalNomal()) || (1 == GetLoidAuthStatus && GetDateTimeDiff() > 40)) && (1 != MngtGdct)
    }
    else {
      return false;
    }
  }

  function setTipsBeforeTCMSResult() {
    if (CheckLoidFailForCT()) {
      if (1 == IsLAN) {
        setPrograss(1, 90);
        mystepforLANDevice();
        setCookie("StepStatus", "2");
        return;
      }

      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      if (1 == Mngtct) {
        if (1 == IsCTRG) {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于（红色）熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
        } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
        } else {
          document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
        }
        LoidRegResultLog("OLT_Fail");
      }
      else if (1 == MngtScct) {
        if (GetStepStatus() == '2') {
          document.getElementById("regResult").innerHTML = itmsDesc + "业务下发失败。"; 
          LoidRegResultLog("TCMS_CfgFail");
        }
        else if (GetStepStatus() == '0' || GetStepStatus() == '3') {
          document.getElementById("regResult").innerHTML = "注册OLT失败，请检查终端收光功率是否正常、宽带识别码（LOID）和PASSWORD是否正确。";
          LoidRegResultLog("OLT_Fail");
        }

      }
      else if (1 == MngtGdct) {
        document.getElementById("regResult").innerHTML = "终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或LOID是否输入正确" + " （历时" + GetDateTimeDiff() + "秒）。";
      }
      else {
        document.getElementById("regResult").innerHTML = "终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或宽带识别码（LOID）是否输入正确" + " （历时" + GetDateTimeDiff() + "秒）。";
        LoidRegResultLog("OLT_Fail");
      }
      if (GetDateTimeDiff() > 300 && 1 != MngtGdct) {
        clearTimeout(timer);
      }
      setCookie("StepStatus", "4");
    }
    else if (GetStepStatus() == '0') {
      if (1 == IsLAN) {
        setPrograss(1, 90);
        mystepforLANDevice();
        setCookie("StepStatus", "2");
        return;
      }

      if (1 == MngtGdct && 1 == GetLoidAuthStatus && GetDateTimeDiff() > 40) {
        setPrograss(1, 69);
        document.getElementById('percent').innerHTML = "23%";
        document.getElementById("regResult").innerHTML = "终端注册OLT失败，LOID不存在，请重试。";
        setCookie("lastPercent", "0");
        LoidRegResultLog("OLT_Fail");
      }
      else if (GetDateTimeDiff() > 240 && 1 == MngtGdct) {
        setPrograss(1, 71);
        document.getElementById('percent').innerHTML = "24%";
        document.getElementById("regResult").innerHTML = "终端注册OLT超时，请确认PON接入方式和LOID是否与施工单一致。如果都正常，请拨打支撑电话检查OLT的PON板卡是否正常，PON口预部署数据配置是否正常。";
        setCookie("lastPercent", "0");
        clearTimeout(timer);
        LoidRegResultLog("OLT_TimeOut");
      }
      else if (GetDateTimeDiff() > 300 && 1 != MngtGdct) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        clearTimeout(timer);
        if (1 == Mngtct) {
          if (1 == IsCTRG) {
            document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯（红色）是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
          } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
            document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
          } else {
            document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
          }
          LoidRegResultLog("OLT_Fail");
          clearTimeout(timer);
        }
        else if (1 == MngtScct) {
          document.getElementById("regResult").innerHTML = "注册OLT失败!请检查线路后重试。";
          LoidRegResultLog("OLT_Fail");
        }
        else {
          document.getElementById("regResult").innerHTML = "终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或宽带识别码（LOID）是否输入正确" + " （历时" + GetDateTimeDiff() + "秒）。";
          LoidRegResultLog("OLT_Fail");
          clearTimeout(timer);
        }
      }
      else {
        StartRegStatus();

        mystep();
      }
    }
    else if (GetStepStatus() == '2') {

      if (1 != IsLAN) {
        if (1 != IsOntOnline) {
          setCookie("StepStatus", "0");
        }
      }

      StartCheckStatus++;
      if (1 == Mngtct) {
        if (GetDateTimeDiff() > 300) {
          if (CfgMode.toUpperCase() == 'SCCNCATV') {
            document.getElementById("regResult").innerHTML = "到TCMS的通道不通，请联系客服经理或者拨打热线96655。";
          } else {
            document.getElementById("regResult").innerHTML = "到" + itmsDesc + "的通道不通，请联系客户经理。" ;
          }
          clearTimeout(timer);
          LoidRegResultLog("TCMS_NoIP");
        }
        else {
          setPrograss(1, 90);
          if (0 == Wan.length || "RWAN" == CurrentRegisterStep) {
            document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
            if (1 == MngtSdct) {
              var Step2ShowInfo = (1 == IsLAN) ? "正在获取管理IP。" : "注册OLT成功。";
              document.getElementById("regResult").innerHTML = Step2ShowInfo;
            }
            else {
              var Step2ShowInfo = (1 == IsLAN) ? "正在获取管理IP。" : "注册OLT成功，正在获取管理IP。";
              document.getElementById("regResult").innerHTML = Step2ShowInfo;
            }

            setCookie("RegisterStep", "RTCMS");
          }
          else {
            for (i = 0; i < Wan.length; i++) {
              if ((Wan[i].ConnectionStatus == "Connected" && (Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1))
                || ((Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1) && (Wan[i].ConnectionStatus == "Connected") && ("RTCMS" == CurrentRegisterStep))) {
                document.getElementById('percent').innerHTML = "40%" + " （历时" + GetDateTimeDiff() + "秒）";
                if (1 == MngtSdct) {
                  document.getElementById("regResult").innerHTML = "已获得管理IP。";
                  setTimeout("window.location='/loidgregsuccess.asp';", 5000)
                }
                else {
                  document.getElementById("regResult").innerHTML = "已获得管理IP，正在连接" + itmsDesc + "。";
                }

                setCookie("RegisterStep", "SBSS");
                break;
              }
              else {
                document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
                if (1 == MngtSdct) {
                  var Step2ShowInfo = (1 == IsLAN) ? "正在获取管理IP。" : "注册OLT成功。";
                  document.getElementById("regResult").innerHTML = Step2ShowInfo;
                }
                else {
                  var Step2ShowInfo = (1 == IsLAN) ? "正在获取管理IP。" : "注册OLT成功，正在获取管理IP。";
                  document.getElementById("regResult").innerHTML = Step2ShowInfo;
                }
                CheckDetailInfo = 1;
              }
            }
          }
        }
      }
      else if (1 == MngtGdct) {
        if (GetDateTimeDiff() > 120) {
          setPrograss(1, 145);
          document.getElementById('percent').innerHTML = "49%";
          var Step2ShowInfo = (1 == IsLAN) ? "终端获取管理地址失败。请拨打支撑电话检查终端到BRAS通道及BRAS地址池配置是否正常。" : "终端注册OLT成功，获取管理地址失败。请拨打支撑电话检查终端到BRAS通道及BRAS地址池配置是否正常。";
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("lastPercent", "0");
          clearTimeout(timer);
          LoidRegResultLog("TCMS_NoIP");
        }
        else {
          for (i = 0; i < Wan.length; i++) {
            if ((Wan[i].ConnectionStatus == "Connected" && Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1)
              || ((Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1) && (Wan[i].ConnectionStatus == "Connected") && ("RTCMS" == CurrentRegisterStep))) {
              /*广东电信，客户要显示所有4个注册阶段*/
              var GdTR069WanStatus = GetWebCookie("GdTR069WanStatus");
              if (GdTR069WanStatus == null || GdTR069WanStatus == "" || GdTR069WanStatus < "1") {
                prograssPercent = parseInt(26 + (23 * GetDateTimeDiff()) / (2 * 60));
                if (prograssPercent > 48) {
                  prograssPercent = 48;
                }
                setPrograss(1, (prograssPercent * 297) / 100);
                document.getElementById('percent').innerHTML = prograssPercent + "%";
                var Step2ShowInfo = (1 == IsLAN) ? "终端正在获取管理地址，请等待；" : "终端注册OLT成功，正在获取管理地址，请等待；";
                document.getElementById("regResult").innerHTML = Step2ShowInfo;
                setCookie("lastPercent", prograssPercent);
                setCookie("GdTR069WanStatus", "1");
              }
              else {
                setPrograss(1, 149);
                document.getElementById('percent').innerHTML = "50%";
                var Step2ShowInfo = (1 == IsLAN) ? "终端获取管理地址成功；" : "终端注册OLT成功，获取管理地址成功；";
                document.getElementById("regResult").innerHTML = Step2ShowInfo;
                setCookie("lStartTime", new Date());
                //只用于广东电信跳转提示
                setCookie("StepStatus", "5");
                setCookie("lastPercent", "50");
                setCookie("GdTR069WanStatus", "2");
                setCookie("RegisterStep", "SBSS");
              }
              break;
            }
            else {
              prograssPercent = parseInt(26 + (23 * GetDateTimeDiff()) / (2 * 60));
              if (prograssPercent > 48) {
                prograssPercent = 48;
              }
              setPrograss(1, (prograssPercent * 297) / 100);
              document.getElementById('percent').innerHTML = prograssPercent + "%";
              var Step2ShowInfo = (1 == IsLAN) ? "终端正在获取管理地址，请等待。" : "终端注册OLT成功，正在获取管理地址，请等待。";
              document.getElementById("regResult").innerHTML = Step2ShowInfo;
              setCookie("lastPercent", prograssPercent);
              CheckDetailInfo = 1;
            }
          }
        }
      }
      else if (1 == MngtFjct) {
        if (GetDateTimeDiff() > 300) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          if (CfgMode.toUpperCase() == 'SCCNCATV') {
            document.getElementById("regResult").innerHTML = "终端到TCMS的通道不通，请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
          } else {
            document.getElementById("regResult").innerHTML = "终端到" + itmsDesc + "的通道不通，请找支撑经理处理"+" （历时"+GetDateTimeDiff()+"秒）。" ;
          }
          clearTimeout(timer);
          LoidRegResultLog("TCMS_NoIP");
        }
        else {
          setPrograss(1, 90);
          document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
          var Step2ShowInfo = (1 == IsLAN)?"终端正在向" + itmsDesc + "平台发起注册。":"终端在OLT已注册成功，下一步是终端向" + itmsDesc + "平台发起注册。";
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("RegisterStep", "SBSS");
        }
      }
      else if (1 == MngtScct) {
        if (GetDateTimeDiff() > 300) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";

          for (i = 0; i < Wan.length; i++) {
            if ((Wan[i].ConnectionStatus == "Connected" && Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1)
              || ((Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1) && (Wan[i].ConnectionStatus == "Connected") && ("RTCMS" == CurrentRegisterStep))) {
              document.getElementById("regResult").innerHTML = "注册" + itmsDesc + "平台失败。"; //更改了ACS URL
              LoidRegResultLog("TCMS_CfgFail");
              break;
            }
            else {
              document.getElementById("regResult").innerHTML = itmsDesc + "业务下发失败。";
              CheckDetailInfo = 1;
              LoidRegResultLog("TCMS_RegFail");
            }
          }
          clearTimeout(timer);
        }
        else {
          if (Wan.length == 0 || "RWAN" == CurrentRegisterStep) {
            setPrograss(1, 120);
            document.getElementById('percent').innerHTML = "40%";
            document.getElementById("regResult").innerHTML = "终端正在获取管理地址。";
            setCookie("RegisterStep", "RTCMS");
          }
          else {
            for (i = 0; i < Wan.length; i++) {
              if ((Wan[i].ConnectionStatus == "Connected" && (Wan[i].X_HW_SERVICELIST.indexOf("TR069") != -1))) {
                setPrograss(1, 120);
                document.getElementById('percent').innerHTML = "40%";
                document.getElementById("regResult").innerHTML = "终端已获取管理地址成功，下一步将注册" + itmsDesc + "平台。";
                setCookie("RegisterStep", "SBSS");
                break;
              }
              else {
                setPrograss(1, 120);
                document.getElementById('percent').innerHTML = "40%";
                document.getElementById("regResult").innerHTML = "终端正在获取管理地址。";
                CheckDetailInfo = 1;
              }
            }
          }

        }
      }
      else {
        if (GetDateTimeDiff() > 120) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          if (CfgMode.toUpperCase() == 'SCCNCATV') {
            document.getElementById("regResult").innerHTML = "终端到TCMS的通道不通，请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
          } else {
            document.getElementById("regResult").innerHTML = "终端到" + itmsDesc + "的通道不通，请找支撑经理处理"+" （历时"+GetDateTimeDiff()+"秒）。" ;
          }
          clearTimeout(timer);
          LoidRegResultLog("TCMS_NoIP");
        }
        else {
          setPrograss(1, 90);
          document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
          var Step2ShowInfo = (1 == IsLAN)?"终端正在向" + itmsDesc + "平台发起注册。":"终端在OLT已注册成功，下一步是终端向" + itmsDesc + "平台发起注册。";
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("RegisterStep", "SBSS");
        }
      }
    }
    //注册5分钟超时提示
    else if (GetStepStatus() == '3') {
      //广东电信注册OLT 4分钟超时
      if (1 == IsLAN) {
        setPrograss(1, 90);
        document.getElementById('percent').innerHTML = "30%" + " （历时" + GetDateTimeDiff() + "秒）";
        document.getElementById("regResult").innerHTML = "注册超时，请检查接入方式和LOID是否与施工单一致。如果都正常，请找支撑经理处理。";
        clearTimeout(timer);
        return;
      }

      if (1 == MngtGdct) {
        if (GetDateTimeDiff() > 240) {
          setPrograss(1, 71);
          document.getElementById('percent').innerHTML = "24%";
          document.getElementById("regResult").innerHTML = "终端注册OLT超时，请确认PON接入方式和LOID是否与施工单一致。如果都正常，请拨打支撑电话检查OLT的PON板卡是否正常，PON口预部署数据配置是否正常。";
          clearTimeout(timer);
          LoidRegResultLog("OLT_TimeOut");
        }
        else {
          StartRegStatus();
          CheckOnlineCnt = 0;
          setCookie("StepStatus", "0");

        }
        setCookie("lastPercent", "0");

      }
      else if (1 != MngtGdct) {
        if (1 == MngtScct) {
          if (GetDateTimeDiff() > 120) {
            document.getElementById("regResult").innerHTML = "注册OLT失败!请检查线路后重试。";
            clearTimeout(timer);
            LoidRegResultLog("OLT_Fail");
          }
          else {
            StartRegStatus();
            CheckOnlineCnt = 0;
            setCookie("StepStatus", "0");
          }
        }
        else if (1 == Mngtct) {
          if (GetDateTimeDiff() > 180) {
            setPrograss(0, 0);
            clearTimeout(timer);
            document.getElementById('percent').innerHTML = "";
            if (1 == IsCTRG) {
              document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯（红色）是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
            } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
            } else {
              document.getElementById("regResult").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理（历时" + GetDateTimeDiff() + "秒）。";
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
        else if (1 == MngtGdct) {
          if (GetDateTimeDiff() > 300) {
            setPrograss(0, 0);
            clearTimeout(timer);
            document.getElementById('percent').innerHTML = "";
            document.getElementById("regResult").innerHTML = "终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或LOID是否输入正确" + " （历时" + GetDateTimeDiff() + "秒）。";
            clearTimeout(timer);
          }
          else {
            StartRegStatus();
            CheckOnlineCnt = 0;
            setCookie("StepStatus", "0");
          }
        }
        else {
          if (GetDateTimeDiff() > 300) {
            setPrograss(0, 0);
            clearTimeout(timer);
            document.getElementById('percent').innerHTML = "";
            document.getElementById("regResult").innerHTML = "终端在OLT上注册失败，请检查光纤是否插接正常、或收光功率是否正常、或宽带识别码（LOID）是否输入正确" + " （历时" + GetDateTimeDiff() + "秒）。";
            LoidRegResultLog("OLT_Fail");
            clearTimeout(timer);
          }
          else {
            StartRegStatus();
            CheckOnlineCnt = 0;
            setCookie("StepStatus", "0");
          }
        }
      }
    }
    else if (GetStepStatus() == '5') {
      StartCheckStatus++;
      if (1 == MngtGdct) {
        //超时时间2分钟
        if (GetDateTimeDiff() > 120) {
          setPrograss(1, 210);
          document.getElementById('percent').innerHTML = "71%";
          document.getElementById("regResult").innerHTML = "终端向" + itmsDesc + "注册失败，正在Ping上层链路是否正常，请等待。" ;
          StartPingDiagnose();
          setCookie("lastPercent", "0");
          setCookie("lStartTime", new Date());
          setCookie("StepStatus", "6");
          LoidRegResultLog("TCMS_RegFail");
        }
        else {
          prograssPercent = parseInt(51 + (20 * GetDateTimeDiff()) / (2 * 60));
          if (prograssPercent > 70) {
            prograssPercent = 70;
          }
          setPrograss(1, (prograssPercent * 297) / 100);
          document.getElementById('percent').innerHTML = prograssPercent + "%";
          var Step2ShowInfo = (1 == IsLAN)?"终端正在向" + itmsDesc + "发送注册请求，请等待；":"终端注册OLT成功，获取管理地址成功，正在向" + itmsDesc + "发送注册请求，请等待；";
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("lastPercent", prograssPercent);
          setCookie("GdTR096WanIp", 1);
        }
      }
    }
    else if (GetStepStatus() == '6') {
      if (1 == MngtGdct) {
        setPrograss(1, 215);
        document.getElementById('percent').innerHTML = "72%";
        document.getElementById("regResult").innerHTML = "终端向" + itmsDesc + "注册失败，正在Ping上层链路是否正常，请等待；";
        LoidRegResultLog("TCMS_RegFail");
        if ((parseInt(PingResult.SuccessCount) > 0) || (parseInt(PingResult.FailureCount) > 0)) {
          setCookie("lastPercent", "0");
          setCookie("StepStatus", "7");
        }
      }
    }
    else if (GetStepStatus() == '7') {
      if (1 == MngtGdct) {
        if (parseInt(PingResult.SuccessCount) > 0) {
          setPrograss(1, 220);
          document.getElementById('percent').innerHTML = "74%";
          var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "失败，上层链路正常。请拨打支撑电话查询" + itmsDesc + "平台终端是否在线，并重新注册，跟踪终端注册报文。";
          var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "失败，上层链路正常。请拨打支撑电话查询" + itmsDesc + "平台终端是否在线，并重新注册，跟踪终端注册报文。";
          var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          LoidRegResultLog("TCMS_RegFail");
        }
        else {
          setPrograss(1, 218);
          document.getElementById('percent').innerHTML = "73%";
          var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "失败，上层链路不通。请拨打支撑电话检查终端到" + itmsDesc + "路由是否正常，" + itmsDesc + "平台是否正常。";
          var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "失败，上层链路不通。请拨打支撑电话检查终端到" + itmsDesc + "路由是否正常，" + itmsDesc + "平台是否正常。";
          var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          LoidRegResultLog("TCMS_RegFail");
        }
      }
      setCookie("lastPercent", "0");
    }
    else {
      //拔掉光纤把时间清一下
      if (GetStepStatus() == '4') {
        setCookie("lStartTime", new Date());
      }
      if ((1 != MngtScct) || (IsOpticalNomal())) {
        StartRegStatus();
        setCookie("StepStatus", "0");
      }
      else {
        setCookie("StepStatus", "2");
      }
    }
  }

  /* 条件：第一次注册或上次注册未成功
     四川电信：注册成功，下发业务成功。
     福建电信：
        1 ProvisioningCode节点为空：TCMS平台数据下发成功，共下发了宽带、语音、ITV三个业务。
    2 ProvisioningCode节点非空：TCMS平台数据下发成功，共下发了" + Infos.ProvisioningCode +"&nbsp;&nbsp;"+ strProvisioning.length + " 个业务。
   */
  function getRegSuccessTips() {
    var strProvisioning = Infos.ProvisioningCode.split(',');
    var strNewProvisioning = '';
    var strNum;

    LoidRegResultLog("TCMS_CfgSuccess");

    return "下发业务成功。";
  }

  /*注册次数是否已经达到上限*/
  function IsRegTimesToLimits() {
    return parseInt(Infos.Times) >= parseInt(Infos.Limits);
  }

  /* 设置广东电信result=1时的进度条 */
  function SetGdctForResult1(timer) {
    var GdDispStatus = GetWebCookie("GdDispStatus");
    if (GdDispStatus == null || GdDispStatus == "" || GdDispStatus < "1") {
      setPrograss(1, 225);
      document.getElementById('percent').innerHTML = "75%";
      var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "成功；";
      var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "成功；";
      var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
      document.getElementById("regResult").innerHTML = Step2ShowInfo;
      setCookie("GdDispStatus", "1");
    }
    else if (GdDispStatus == "1") {
      prograssPercent = parseInt(76 + (23 * GetDateTimeDiff()) / (6 * 60));
      if (prograssPercent > 98) {
        prograssPercent = 98;
      }
      setPrograss(1, (prograssPercent * 297) / 100);
      document.getElementById('percent').innerHTML = prograssPercent + "%";
      var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "成功，正在下发业务，请等待；";
      var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "成功，正在下发业务，请等待；";
      var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
      document.getElementById("regResult").innerHTML = Step2ShowInfo;
      setCookie("lastPercent", prograssPercent);
      setCookie("GdDispStatus", "2");
    }
    else {
      document.getElementById('percent').innerHTML = "100%";
      setCookie("lastPercent", "0");
      document.getElementById("regResult").innerHTML = getRegSuccessTips();
      clearTimeout(timer);
      setCookie("GdDispStatus", "3");
    }
  }

  function LoadFrame() {
    CheckWanInfo();

    LoadFrameInfo(2000);
  }

  function GetRegInfoForFirstStep() {
    setPrograss(1, 150);
    if (1 == MngtFjct || 1 == MngtCqct) {
      document.getElementById('percent').innerHTML = "50%" + "（历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = "终端在" + itmsDesc + "平台注册成功，下一步是" + itmsDesc + "平台下发数据。";
    }
    else if (1 == MngtScct) {
      document.getElementById('percent').innerHTML = "50%";
      document.getElementById("regResult").innerHTML = "终端注册" + itmsDesc + "平台成功，下一步" + itmsDesc + "平台将下发数据。";
    }
    else if (1 == Mngtct) {
      document.getElementById('percent').innerHTML = "50%" + "（历时" + GetDateTimeDiff() + "秒）";
      if (1 == MngtSdct) {
        document.getElementById("regResult").innerHTML = "注册" + itmsDesc + "成功。";
      }
      else {
        document.getElementById("regResult").innerHTML = "终端合法，等待业务下发。";
      }
    }
    else if (1 == MngtGdct) {
      setPrograss(1, 225);
      document.getElementById('percent').innerHTML = "75%";
      var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "成功。";
      var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "成功。";
      var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
      document.getElementById("regResult").innerHTML = Step2ShowInfo;
      setCookie("lastPercent", "75");
      setCookie("lStartTime", new Date());
      setCookie("GdDispStatus", "1");
    }
    else {
      document.getElementById('percent').innerHTML = "50%";
      document.getElementById("regResult").innerHTML = "注册成功。";
    }

    return;
  }

  function GetRegInfoForSecondStep() {
    if (1 == MngtCqct) {
      setPrograss(1, 180);
      document.getElementById('percent').innerHTML = "60%" + "（历时" + GetDateTimeDiff() + "秒）";
      var LanDesInfoStr = itmsDesc + "平台正在进行数据下发，请勿下电或拔插网线。";
      var PonDesInfoStr = "正在下发业务，请等待。";
      var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
      document.getElementById("regResult").innerHTML = Step2ShowInfo;
    }
    else if (1 == MngtFjct) {
      if (GetDateTimeDiff() > 600) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        document.getElementById("regResult").innerHTML = itmsDesc + "下发业务超时，请重新注册或找支撑经理处理"+"（历时"+GetDateTimeDiff()+"秒）。" ;       
        LoidRegResultLog("TCMS_CfgTimeout");
        clearTimeout(timer);
      }
      else {
        setPrograss(1, 180);
        document.getElementById('percent').innerHTML = "60%" + "（历时" + GetDateTimeDiff() + "秒）";
        var LanDesInfoStr = itmsDesc + "平台正在进行数据下发，请勿下电或拔插网线。";
        var PonDesInfoStr = itmsDesc + "平台正在进行数据下发，请勿下电或拔插光纤。";
        var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
        document.getElementById("regResult").innerHTML = Step2ShowInfo;
      }
    }
    else if (1 == MngtScct) {
      setPrograss(1, 180);
      document.getElementById('percent').innerHTML = "60%";
      var LanDesInfoStr = itmsDesc + "平台正在下发数据，请勿下电或拔插网线。";
      var PonDesInfoStr = itmsDesc + "平台正在下发数据，请勿下电或拔插光纤。";
      var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
      document.getElementById("regResult").innerHTML = Step2ShowInfo;
    }
    else if (1 == Mngtct) {
      try {
        var strProvisioning = RegPercents.shift().split(',');
        setPrograss(1, (strProvisioning[0] * 297) / 100);
      } catch (e) {
        setPrograss(1, (60 * 297) / 100);
      }

      if (("0" == Infos.ServiceNum) && ("" == Infos.ProvisioningCode)) {
        document.getElementById('percent').innerHTML = strProvisioning[0] + "%" + "（历时" + GetDateTimeDiff() + "秒）";
        var LanDesInfoStr = itmsDesc + "平台正在下发业务数据，请勿断电或拔网线。";
        var PonDesInfoStr = "正在下发业务，请等待。";
        var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
        document.getElementById("regResult").innerHTML = Step2ShowInfo;
      }
      else {
        var var_length = strProvisioning.length;
        var var_servername = strProvisioning[var_length - 1].toUpperCase();
        var strServiceName = "";

        if (var_servername == "IPTV" || var_servername == "ITV") {
          strServiceName += "iTV";
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

        document.getElementById('percent').innerHTML = strProvisioning[0] + "%" + "（历时" + GetDateTimeDiff() + "秒）";
        var LanDesInfoStr = itmsDesc + "平台正在下发"+ strServiceName + "业务数据，请勿断电或拔网线。";
        var PonDesInfoStr = itmsDesc + "平台正在下发"+ strServiceName + "业务数据，请勿断电或拔光纤。";
        var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
        document.getElementById("regResult").innerHTML = Step2ShowInfo;
      }
    }
    else if (1 == MngtGdct) {
      //超时时间为4分钟，客户要求和规范一致。
      if (GetDateTimeDiff() > 240) {
        setPrograss(1, 295);
        document.getElementById('percent').innerHTML = "99%";
        document.getElementById("regResult").innerHTML = itmsDesc + "下发业务超时，请重试。" ;
        setCookie("lastPercent", "0");
        clearTimeout(timer);
        LoidRegResultLog("TCMS_CfgTimeout");
      }
      else {
        /*广东电信，客户要显示所有4个注册阶段*/
        var GdDispStatus = GetWebCookie("GdDispStatus");
        if (GdDispStatus == null || GdDispStatus == "" || GdDispStatus < "1") {
          setPrograss(1, 225);
          document.getElementById('percent').innerHTML = "75%";
          var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "成功。";
          var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "成功。";
          var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("GdDispStatus", "1");
        }
        else {
          prograssPercent = parseInt(76 + (23 * GetDateTimeDiff()) / (6 * 60));
          if (prograssPercent > 98) {
            prograssPercent = 98;
          }
          setPrograss(1, (prograssPercent * 297) / 100);
          document.getElementById('percent').innerHTML = prograssPercent + "%";
          var LanDesInfoStr = "终端获取管理地址成功，注册" + itmsDesc + "成功，正在下发业务，请等待。";
          var PonDesInfoStr = "终端注册OLT成功，获取管理地址成功，注册" + itmsDesc + "成功，正在下发业务，请等待。";
          var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;
          document.getElementById("regResult").innerHTML = Step2ShowInfo;
          setCookie("lastPercent", prograssPercent);
          setCookie("GdDispStatus", "2");
        }
      }
    }
    else {
      setPrograss(1, 180);
      document.getElementById('percent').innerHTML = "60%";
      document.getElementById("regResult").innerHTML = "注册成功，正在下发业务，请等待。";
    }

    return;
  }

  function GetRegInfoForThreeStep() {
    setPrograss(1, 298);
    if (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct) {
      document.getElementById('percent').innerHTML = "100%" + "（历时" + GetDateTimeDiff() + "秒）";
      document.getElementById("regResult").innerHTML = getRegSuccessTips();
      clearTimeout(timer);
    }
    else {
      document.getElementById('percent').innerHTML = "100%";
      document.getElementById("regResult").innerHTML = "注册成功，下发业务成功。";
      LoidRegResultLog("TCMS_CfgSuccess");
    }

    return;
  }

  function stRegisterStep(stepnum, statusvalue, resultvalue) {
    this.stepnum = stepnum;
    this.statusvalue = statusvalue;
    this.resultvalue = resultvalue;
  }


  var StepByStepArray = new Array(new stRegisterStep(0, 99, 99),
    new stRegisterStep(1, 99, "other"),
    new stRegisterStep(1, "other", 99),
    new stRegisterStep(2, 0, 0),
    new stRegisterStep(3, 0, 1),
    new stRegisterStep(3, 0, 2), null);

  function GetRegdesByStep(StepSRinfo, currentstep) {
    $("#percentin").show();
    if (StepSRinfo == 0) {
      /* 补充显示status = 0,result = 99的状态 */
      GetRegInfoForFirstStep();
      setCookie("SRStepInfo", "1;0;99");
      return "StopOneTime";
    }
    else if (StepSRinfo == 1) {
      /* 补充显示status = 0,result = 0的状态 */
      $("#percentin").show();
      GetRegInfoForSecondStep();
      setCookie("SRStepInfo", "2;0;0");
      return "StopOneTime";
    }
    else {
      return "goon";
    }
  }

  function GetProcessByStep(Infos) {
    var RegisterSRStep = GetWebCookie('SRStepInfo');
    if (RegisterSRStep == null || RegisterSRStep == "") {
      setCookie("SRStepInfo", "0;99;99");
      RegisterSRStep = "0;99;99";
    }
    var StepSRinfo = RegisterSRStep.split(";")[0];
    var StatusInfo = RegisterSRStep.split(";")[1];
    var ResultInfo = RegisterSRStep.split(";")[2];
    var CurrentStepNum = StepSRinfo;
    var StepInfoArray = null;

    if ((Infos.Status == 99 && Infos.Result != 99)
      || (Infos.Status != 99 && Infos.Result == 99)) {
      CurrentStepNum = 1;
    }

    for (var index = 0; index < StepByStepArray.length - 1; index++) {

      if ((Infos.Status == StepByStepArray[index].statusvalue && Infos.Result == StepByStepArray[index].resultvalue)) {
        StepInfoArray = StepByStepArray[index];
        CurrentStepNum = StepByStepArray[index].stepnum;
      }
    }

    var StepSpan = CurrentStepNum - StepSRinfo;
    if (0 == StepSpan || 1 == StepSpan) {
      /* 当前进度没有变更或者只前进了一步，保持原有流程不变 */
      var SRStepInfoStr = CurrentStepNum + ";" + Infos.Status + ";" + Infos.Result;
      setCookie("SRStepInfo", SRStepInfoStr);
      return "goon";
    }

    return GetRegdesByStep(StepSRinfo, CurrentStepNum);
  }



  function LoadFrameInfo(time) {
    CurrentRegisterStep = GetWebCookie('RegisterStep');
    if (CurrentRegisterStep == null || CurrentRegisterStep == "") {
      setCookie("RegisterStep", "RPON");
      CurrentRegisterStep = "RPON";
    }

    /* 启动超时定时器 */
    setRefreshInterval(time);

    /* 对于广东E8C，注册过程中，进行光路检测，光路故障与非光路故障区分提示 */
    if (1 != IsLAN) {
      if ((1 == MngtGdct) && (('1' == GetGDCTOpticAbnormal) || (!IsOpticalNomal()))) {
        var lastPercent = GetWebCookie('lastPercent');
        /* 存在光路故障 */
        if (lastPercent != null && lastPercent != "" && lastPercent != "0") {
          var prograss = parseInt((lastPercent * 297) / 100);
          setPrograss(1, prograss);
          document.getElementById('percent').innerHTML = lastPercent + "%";
          document.getElementById("regResult").innerHTML = '终端注册光信号丢失，请检查光线路的光功率是否正常，终端光模块是否正常。<font style="color: red;">请点击返回，重新注册。</font>';
          LoidRegResultLog("OLT_Fail");
          return;
        }
      }
    }

    /*福建电信或是四川电信模式下，上次已经注册成功，提示恢复出厂设置*/
    if (RegPeriodFlag == 2 && (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct)) {
      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      document.getElementById("regResult").innerHTML = "设备已注册，无需再注册，需恢复出厂配置才可再注册" + "（历时" + GetDateTimeDiff() + "秒）。";
      clearTimeout(timer);
      return;
    }

    /*福建电信或是四川电信模式下，已经提交注册请求，但是TCMS还没有返回任何结果，即此时的Result和Status为无效值*/
    if (RegPeriodFlag == 0 && (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct)) {
      setTipsBeforeTCMSResult();
      return;
    }


    /* 对于广东，各个注册阶段都会进行光路检测，若存在光路异常，提示失败，无需重注册 */
    if (((1 != IsOntOnline) || (0 != parseInt(Infos.InformStatus)))) {
      Infos.Status = 99;
    }

    if (CurrentRegisterStep == "RPON" || CurrentRegisterStep == "RWAN" || CurrentRegisterStep == "RTCMS") {
      setTipsBeforeTCMSResult();
      return;
    }

    try {
      var CtrlStatus = GetProcessByStep(Infos);
      if ("goon" != CtrlStatus) {
        return null;
      }

    } catch (e) {
      $("#percent").hide();
      window.location = 'http://' + br0Ip + ':' + httpport;
      return null;
    }


    if (Infos != null) {

      if (parseInt(Infos.Status) == 0) {
        StartCheckStatus++;
        if (parseInt(Infos.Result) == 99) {
          GetRegInfoForFirstStep();
        }
        else if (parseInt(Infos.Result) == 0) {
          GetRegInfoForSecondStep();
        }
        else if (parseInt(Infos.Result) == 1) {
          GetRegInfoForThreeStep();
        }
        else {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          LoidRegResultLog("TCMS_CfgFail");
          if (1 == MngtFjct || 1 == MngtCqct) {
            document.getElementById("regResult").innerHTML = itmsDesc + "平台业务未下发或业务下发异常，请找支撑经理处理"+"（历时"+GetDateTimeDiff()+"秒）。";
            clearTimeout(timer);

          }
          else if (1 == Mngtct) {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "TCMS下发业务异常！请联系客服经理或者拨打热线96655（历时" + GetDateTimeDiff() + "秒）。";
            } else {
              document.getElementById("regResult").innerHTML = itmsDesc + "下发业务异常！请联系客户经理（历时"+GetDateTimeDiff()+"秒）。";
            }
            clearTimeout(timer);
          }
          else if (1 == MngtScct) {
            document.getElementById("regResult").innerHTML = "注册" + itmsDesc + "平台成功，" + itmsDesc + "平台业务未下发或业务下发异常。";
          }
          else {
            document.getElementById("regResult").innerHTML = "注册成功，下发业务失败。";
          }
        }
      }
      else if (parseInt(Infos.Status) == 1) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        StartCheckStatus++;
        LoidRegResultLog("TCMS_RegFail");
        if (1 == MngtFjct || 1 == MngtCqct) {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "输入的PASSWORD（密码）不正确，注册失败，请支撑经理处理" + "（历时" + GetDateTimeDiff() + "秒）。";
            clearTimeout(timer);
          }
          else {
            document.getElementById("regResult").innerHTML = "输入的PASSWORD（密码）不正确，请核实后重新注册（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）" + "（历时" + GetDateTimeDiff() + "秒）。";
            clearTimeout(timer);
          }
        }
        else if (1 == Mngtct) {
          if (IsRegTimesToLimits()) {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请3分钟后重试，如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请3分钟后重试或联系客户经理。";
            }
          }
          else {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请检查宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请检查宽带识别码（LOID）和密码是否正确或联系客户经理。";
            }
          }
        }
        else if (1 == MngtScct) {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "Password不存在，注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "Password不存在，请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
        else {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "身份证不存在！注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "身份证不存在！请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
      }
      else if (parseInt(Infos.Status) == 2) {
        StartCheckStatus++;
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        LoidRegResultLog("TCMS_RegFail");
        if (1 == MngtFjct || 1 == MngtCqct) {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "输入的宽带识别码（LOID）在" + itmsDesc + "平台不存在，注册失败，请找支撑经理处理"+"（历时"+GetDateTimeDiff()+"秒）。";
            clearTimeout(timer);
          }
          else {
            document.getElementById("regResult").innerHTML = "输入的宽带识别码（LOID）在" + itmsDesc + "平台不存在，注册失败，请核实后重新注册！请重试（剩余尝试次数：" + (parseInt(Infos.Limits)-parseInt(Infos.Times)) + "）"+"（历时"+GetDateTimeDiff()+"秒）。";
            clearTimeout(timer);
          }
        }
        else if (1 == MngtScct) {
          if (parseInt(Infos.Times) >= parseInt(Infos.Limits)) {
            document.getElementById("regResult").innerHTML = "宽带识别码（LOID）不存在，注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "宽带识别码（LOID）不存在，请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
        else if (1 == Mngtct) {
          if (IsRegTimesToLimits()) {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请3分钟后重试，如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请3分钟后重试或联系客户经理。";
            }
          }
          else {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请检查宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请检查宽带识别码（LOID）和密码是否正确或联系客户经理。";
            }
          }
        }
        else {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "宽带账号不存在！注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "宽带账号不存在！请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
      }
      else if (parseInt(Infos.Status) == 3) {
        StartCheckStatus++;
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        LoidRegResultLog("TCMS_RegFail");
        if (1 == MngtFjct || 1 == MngtCqct) {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "身份证与宽带账号不匹配！注册失败（历时" + GetDateTimeDiff() + "秒）。";
            clearTimeout(timer);
          }
          else {
            document.getElementById("regResult").innerHTML = "身份证与宽带账号不匹配！请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）" + "（历时" + GetDateTimeDiff() + "秒）。";
            clearTimeout(timer);
          }
        }
        else if (1 == Mngtct) {
          if (IsRegTimesToLimits()) {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请3分钟后重试，如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请3分钟后重试或联系客户经理。";
            }
          }
          else {
            if (CfgMode.toUpperCase() == 'SCCNCATV') {
              document.getElementById("regResult").innerHTML = "在TCMS上注册失败！请检查宽带识别码（LOID）和密码是否正确。如问题仍未解决，请联系客服经理或者拨打热线96655。";
            } else {
              document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册失败！请检查宽带识别码（LOID）和密码是否正确或联系客户经理。";
            }
          }
        }
        else if (1 == MngtScct) {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "宽带识别码（LOID）和Password不匹配，注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "宽带识别码（LOID）和Password不匹配，请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
        else {
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "身份证与宽带账号不匹配！注册失败。";
          }
          else {
            document.getElementById("regResult").innerHTML = "身份证与宽带账号不匹配！请重试（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }
        }
      }
      else if (parseInt(Infos.Status) == 4) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";

        if (1 == MngtFjct || 1 == MngtCqct) {
          document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试" + "（历时" + GetDateTimeDiff() + "秒）。";
          LoidRegResultLog("TCMS_Timeout");
          clearTimeout(timer);
        }
        else if (1 == Mngtct) {
          if (CfgMode.toUpperCase() == 'SCCNCATV') {
            document.getElementById("regResult").innerHTML = "在TCMS上注册超时！请检查线路后重试。如问题仍未解决，请联系客服经理或者拨打热线96655。";
          } else {
            document.getElementById("regResult").innerHTML = "在" + itmsDesc + "上注册超时！请检查线路后重试或联系客户经理。";
          }
          LoidRegResultLog("TCMS_Timeout");
        }
        else if (1 == MngtScct) {
          document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。";
          LoidRegResultLog("TCMS_Timeout");
        }
        else {
          document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。";
          LoidRegResultLog("TCMS_Timeout");
        }
      }
      else if (parseInt(Infos.Status) == 97) {
        setPrograss(0, 0);
        LoidRegResultLog("TCMS_RegRepeat");
        clearTimeout(timer);
        document.getElementById('percent').innerHTML = "";
        document.getElementById("regResult").innerHTML = "已经注册成功，无需再注册。";

      }
      else if (parseInt(Infos.Status) == -1) {
        setPrograss(0, 0);
        LoidRegResultLog("TCMS_RegFail");
        document.getElementById('percent').innerHTML = "";
        document.getElementById("regResult").innerHTML = Infos.Desc;

      }
      else {
        setTipsBeforeTCMSResult();
        return;
      }

    }
    else {
      setTipsBeforeTCMSResult();
      return;
    }
  }
  function IsCTRGAreaInformBind2() {
    var x;
    var CfgKey = '<%HW_WEB_GetCfgMode();%>';
    var Customs = ["NMGCT", "SDCT"];
    var IsCtrg = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
    if (IsCtrg == '1') {
      for (x in Customs) {
        if (Customs[x] == CfgKey.toUpperCase()) {
          return true;
        }
      }
    }
    return false;
  }
  function JumpTo() {
    clearTimeout(timer);

    if (1 != simcardstatus) {
      if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV')) {
        if (parseInt(Infos.Status) == 97) {
          window.location = "/login.asp";
        }
        else {
          window.location = "/loidreg.asp";
        }
      }
      else if ((parseInt(Infos.Result) == 1) && ((parseInt(Infos.Status) == 0))) {
        if (!IsCTRGAreaInformBind2()) {
          window.location = "/login.asp";
        }
        else {
          window.location = "/loidreg.asp";
        }
      }
      else {
        window.location = "/loidreg.asp";
      }
    }
    else {
      window.location = "../html/ssmp/loid/loid.asp";
    }
  }

  function RestoreDefaultCfgAll() {
    window.location = "/loidgrestore.asp";
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

</script>

<body onLoad="LoadFrame();">
  <form>
    <div align="center">
      <TABLE cellSpacing="0" cellPadding="0" style="width:808px;" align="center" border="0">
        <TBODY>
          <script language="JavaScript" type="text/javascript">
            if (1 == simcardstatus) {
              document.write('<TD style="width:6px;" rowSpan="3"></TD> ');
              document.write('<TABLE cellSpacing="0" cellPadding="0" align="middle" style="width:653px;" border="0">');
            }
            else {
              if (CfgMode.toUpperCase() == 'SHXCNCATV') {
                document.write('<TD><div style="  width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block;" height="70" src="/images/top_img_20K_shxcncatv.jpg" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip + ':' + httpport + '/login.asp" style="display: block;float: right; margin-right: 84px;margin-top: -30px;font-family: 微软雅黑;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
                document.write('<TD><div style="  width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block;" height="50" src="/images/top_sccncatv.jpg" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip + ':' + httpport + '/login.asp" style="display: block;float: right; margin-right: 84px;margin-top: -30px;font-family: 微软雅黑;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              } else if (CfgMode.toUpperCase() == 'HUNCNCATV') {
                document.write('<TD><div style="  width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block;" height="70" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip +':'+ httpport +'/login.asp" style="display: block;float: right; margin-right: 84px;margin-top: -30px;font-family: 微软雅黑;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              } 
              document.write('<TABLE cellSpacing="0" cellPadding="0" align="middle" style="width:808px;" border="0">');
            }
          </script>
        <TBODY>
          <script language="javascript">
            if (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct) {
              document.write('<TD align="center" style="width:653px;height:323px;" >');
            }
            else if (1 == MngtScct) {
              document.write('<TD align="center" style="width:653px;height:323px;" background="/images/register_gdinfo_scct.jpg">');
            }
            else {
              document.write('<TD align="center" style="width:653px;height:323px;" background="/images/register_content.jpg">');
            }
          </script>
          <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
            <TR>
              <TD align="right">
              </TD>
            </TR>
          </TABLE>
          <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">
            <script language="javascript">
              if (1 != IsLAN) {
                if (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct) {
                  document.write('<TD colSpan="2" height="18"></TD>');
                  document.write('<TR>');
                  document.write('<TD align="middle" colSpan="2" height="25" style="font-size: 13px;">提示：在注册过程中不要随意拔插光纤（10分钟内）</TD>');
                  document.write('</TR>');
                  if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                    if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                      document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON终端</TD></TR>');
                    }
                    else {
                      document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON终端</TD></TR>');
                    }
                  }
                  else {
                    if (ontPonMode.toUpperCase() == 'GPON') {
                      if (1 == IsRhGateway) {
                        if (1 == E8CRONGHEFlag) {
                          document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON宽带融合终端</TD></TR>');
                        }
                        else {
                          document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON上行融合智能终端</TD></TR>');
                        }
                      }
                      else if (1 == IsCTRG) {
                        document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON上行天翼网关</TD></TR>');
                      }
                      else {
                        document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON的终端</TD></TR>');
                      }
                    }
                    else {
                      if (1 == IsRhGateway) {
                        if (1 == E8CRONGHEFlag) {
                          document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON宽带融合终端</TD></TR>');
                        }
                        else {
                          document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON上行融合智能终端</TD></TR>');
                        }
                      }
                      else if (1 == IsCTRG) {
                        document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON上行天翼网关</TD></TR>');
                      }
                      else {
                        document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON的终端</TD></TR>');
                      }
                    }
                  }
                }
                else if (1 == MngtScct) {
                  document.write('<TD colSpan="2" height="2"></TD>');
                  document.write('<TR>');
                  if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                    if (1 == IsRhGateway) {
                      if (1 == E8CRONGHEFlag) {
                        document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">GPON宽带融合终端注册</TD>');
                      }
                      else {
                        document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">GPON上行融合智能终端注册</TD>');
                      }
                    }
                    else if (1 == IsCTRG) {
                      document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">GPON上行天翼网关注册</TD>');
                    }
                    else {
                      document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">GPON的终端注册</TD>');
                    }
                  }
                  else {
                    if (1 == IsRhGateway) {
                      if (1 == E8CRONGHEFlag) {
                        document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">EPON宽带融合终端注册</TD>');
                      }
                      else {
                        document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">EPON上行融合智能终端注册</TD>');
                      }
                    }
                    else if (1 == IsCTRG) {
                      document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">EPON上行天翼网关注册</TD>');
                    }
                    else {
                      document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">EPON的终端注册</TD>');
                    }
                  }
                  document.write('</TR>');
                  document.write('<TD colSpan="2" height="32"></TD>');
                }
                else {
                  document.write('<TD colSpan="2" height="15"></TD>');
                  document.write('<TR>');
                  document.write('<TD align="middle" colSpan="2" height="20"></TD>');
                  document.write('</TR>');

                  document.write('<TR>');
                  document.write('<TD valign="bottom" align="right" width="130" height="15"></TD>');
                  document.write('<TD valign="bottom" align="left" width="130"></TD>');
                  document.write('</TR>');
                }
              }
              else {
                if (1 == MngtFjct || 1 == MngtCqct || 1 == Mngtct) {
                  document.write('<TD colSpan="2" height="18"></TD>');
                  document.write('<TR>');
                  document.write('<TD align="middle" colSpan="2" height="25" style="font-size: 13px;">提示：在注册过程中不要随意拔插网线（10分钟内）</TD>');
                  document.write('</TR>');
                  if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                    document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是以太上行终端</TD></TR>');
                  }
                  else {
                    if (1 == IsRhGateway) {
                      document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是以太上行融合智能终端</TD></TR>');
                    }
                    else {
                      document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是以太上行的终端</TD></TR>');
                    }
                  }
                }
                else if (1 == MngtScct) {
                  document.write('<TD colSpan="2" height="2"></TD>');
                  document.write('<TR>');

                  if (1 == IsRhGateway) {
                    document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">以太上行融合智能终端注册</TD>');
                  }
                  else {
                    document.write('<TD align="left" colSpan="2" height="25" style="font-size: 13px;">以太上行的终端注册</TD>');
                  }
                  document.write('</TR>');
                  document.write('<TD colSpan="2" height="32"></TD>');
                }
                else {
                  document.write('<TD colSpan="2" height="15"></TD>');
                  document.write('<TR>');
                  document.write('<TD align="middle" colSpan="2" height="20"></TD>');
                  document.write('</TR>');

                  document.write('<TR>');
                  document.write('<TD valign="bottom" align="right" width="130" height="15"></TD>');
                  document.write('<TD valign="bottom" align="left" width="130"></TD>');
                  document.write('</TR>');
                }
              }
            </script>
            <TR>
              <TD colspan="2" align="center">
                <div id="prograss"><span id="percent" style="font-size:12px;"></span></div>
              </TD>
              <script language="javascript">
                if (1 == MngtSdct) {
                  document.getElementById('percent').style.display = "none";
                }
              </script>
            </TR>
            <TR>
              <TD colspan="2" align="center">
                <script language="JavaScript" type="text/javascript">
                  //if (1 != IsLAN)
                  //{
                  document.write(htmltxt);
	//}
                </script>
              </TD>
            </TR>
            <TR>
              <TD align="middle" colSpan="2" height="4"></TD>
            </TR>
            <TR height="8">
              <TD colspan="2" align="center"><span id="regResult" style="font-size:14px;"></span></TD>
            </TR>
            <TR>
              <TD colspan="2" valign="top" align="right" width="130" height="25" align="center" />
            </TR>
            <TR>
              <script language="javascript">
                document.write('<TD colspan="2" align="center"　height="30">');
                if (1 == MngtFjct || 1 == MngtScct || 1 == MngtCqct || 1 == Mngtct) {
                  if (((2 == RegPeriodFlag) && (1 == IsOntOnline))
                    && (1 != simcardstatus)) {

                    document.write('<input type="button" style="font-size: 14px;margin-left:150px" class="submit" value="返 回" onclick="JumpTo();"/>');

                    document.write('<input type="button" style="font-size: 14px;margin-left:60px" name="resetValue" id="resetValue" class="submit" value="恢复出厂配置" onclick="RestoreDefaultCfgAll();"/>');
                  }
                  else {
                    document.write('<input type="button" class="submit" style="font-size: 14px;" value="返 回" onclick="JumpTo();"/>');
                  }
                }
                else {
                  document.write('<input type="button" class="submit" style="font-size: 14px;" value="返 回" onclick="JumpTo();"/>');
                }
                document.write('</TD>');
              </script>
            </TR>
            <TR>
            </TR>
            <TR>
              <TD align="left" colSpan="2" height="60"></TD>
            </TR>
          </TABLE>
          </TR>
        </TBODY>
      </TABLE>
      </TD>
      </TR>
      </TBODY>
      </TABLE>
    </div>
  </form>
</body>

</html>