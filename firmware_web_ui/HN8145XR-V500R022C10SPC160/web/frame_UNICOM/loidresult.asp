<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <script language="JavaScript" type="text/javascript">
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    var TelNum;
    document.write('<title>中国联通</title>');
    TelNum = '10010号';
  </script>

  <style>
    .input_time {
      border: 0px;
    }

    .addregResult {
      margin-left: 30px;
      font-size: 16px;
    }
  </style>
  <script language="JavaScript" src="../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="javascript">
    var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
    var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
    var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';
    function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum) {
      this.domain = domain;
      this.Result = Result;
      this.Status = Status;
      this.Limits = Limits;
      this.Times = Times;
      this.RegTimerState = RegTimerState;
      this.InformStatus = InformStatus;
      this.ProvisioningCode = ProvisioningCode;
      this.ServiceNum = ServiceNum;
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
      this.ConnectionType = ConnectionType;
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
      this.ConnectionType = ConnectionType;
    }

    function PingResultClass(domain, FailureCount, SuccessCount) {
      this.domain = domain;
      this.FailureCount = FailureCount;
      this.SuccessCount = SuccessCount;
    }

    var opticInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic.RxPower);%>';
    var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|Limit|Times|X_HW_TimeoutState|X_HW_InformStatus|ProvisioningCode, stResultInfo);%>;
    if (null != stResultInfos && null != stResultInfos[0]) {
      var Infos = stResultInfos[0];
    }
    else {
      var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99", "10", "0", "NONE", "1", ""), null);
      var Infos = stResultInfos[0];
    }

    var InfosStatus = Infos.Status;
    var InfosResult = Infos.Result;
    var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
    var WanIp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANIPConnection.{i}, ConnectionStatus||ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANIP);%>;
    var WanPpp = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}, ConnectionStatus|ExternalIPAddress|X_HW_SERVICELIST|ConnectionType|X_HW_TR069FLAG, WANPPP);%>;
    var Wan = new Array();

    var stOnlineStatusInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>';
    var IsOntOnline = stOnlineStatusInfo;
    var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';

    var loadedcolor = '#ec6c00';
    var unloadedcolor = 'FCEAC1';
    var bordercolor = 'url(../images/progress.gif)';
    var barheight = 27;
    var barwidth = 438;
    var ns4 = (document.layers) ? true : false;
    var ie4 = (document.all) ? true : false;
    var PBouter;
    var PBdone;
    var PBbckgnd;
    var txt = '';
    var timer;
    var CheckDetailInfo = 1;
    var StartCheckStatus = 0;
    var RefreshCount = 0;
    var acsUrl = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.ManagementServer.URL);%>';

    var GetLoidAuthStatus = '<%HW_WEB_GetLoidAuthStatus();%>';
    var opticMode = '<%HW_WEB_GetOpticMode();%>'
    var opticType = '<%HW_WEB_GetOpticType();%>';
    var RefreshStop = 0;
    var isExistUserChoice = 1;
    var CheckCnt = 0;
    var RefreshNum = 0;
    var CheckOnlineCnt = 0;
    var ResultTemp = '';

    if (1 == IsLAN) {
      IsOntOnline = 1;
      GetLoidAuthStatus = 0;
    }

    function getLayerStr(isNs4, barheight, barwidth, bordercolor, barheight, unloadedcolor, loadedcolor) {
      var txt = '';
      if (ns4) {
        txt += '<table border=0 cellpadding=0 cellspacing=0><tr><td>';
        txt += '<ilayer name="PBouter" visibility="" height="' + barheight + '" width="' + barwidth + '">';
        txt += '<layer style = " width:' + barwidth + '; height:' + barheight + '; background:' + bordercolor + '; background-repeat: no-repeat;"></layer>';     //txt+='<layer width="'+(barwidth-2)+'" height="'+(barheight-2)+'" bgcolor="'+unloadedcolor+'" top="1" left="1"></layer>';
        txt += '<layer name="PBdone" width="' + (barwidth - 12) + '" height="' + (barheight - 12) + '" bgcolor="' + loadedcolor + '" top="7" left="6"></layer>';
        txt += '</ilayer>';
        txt += '</td></tr></table>';
      } else {
        txt += '<div id="PBouter" style="position:relative; visibility:hidden; background:' + bordercolor + '; width:' + barwidth + 'px; height:' + barheight + 'px; background-repeat: no-repeat;">';   //txt+='<div style="position:absolute; top:1px; left:1px; width:'+(barwidth-2)+'px; height:'+(barheight-2)+'px; background-color:'+unloadedcolor+'; font-size:1px;"></div>';
        txt += '<div id="PBdone" style="position:absolute; top:7px; left:6px; width:0px; height:' + (barheight - 12) + 'px; background-color:' + loadedcolor + '; font-size:1px;"></div>';
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

        if ((Wan[i].ConnectionStatus === "Connected") && (Wan[i].ConnectionType.toUpperCase().indexOf("BRIDGED") < 0)) {
          CheckDetailInfo = 0;
        }
      }

      for (j = 0; WanPpp.length > 1 && j < WanPpp.length - 1; i++, j++) {
        if ("1" == WanPpp[j].X_HW_TR069FLAG) {
          i--;
          continue;
        }
        Wan[i] = WanPpp[j];

        if ((Wan[i].ConnectionStatus === "Connected") && (Wan[i].ConnectionType.toUpperCase().indexOf("BRIDGED") < 0)) {
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

    function CheckUserChoiceStatus() {
      var tmpFlag = 0;
      $.ajax({
        type: "POST",
        async: false,
        cache: false,
        timeout: 3000,
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
        timeout: 2000,
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
        timeout: 2000,
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
            timeout: 2000,
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
            timeout: 2000,
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
            timeout: 2000,
            url: "asp/GetRegResult.asp",
            success: function (data) {
              try {
                Infos = dealDataWithFun(data);
                if (Infos.Status != InfosStatus) {
                  Infos.Result = InfosResult;
                }

                InfosStatus = Infos.Status;
                InfosResult = Infos.Result;
                FreshCountDel();
              } catch (e) {
                ;
              }
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
          timeout: 3000,
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

      if (ontPonMode.toUpperCase() == 'GPON') {
        if (opticType == 1) {
          return opticInfo < -27;
        }
        else if (opticType == 2) {
          return opticInfo < -30;
        }
      }
      else if (ontPonMode.toUpperCase() == 'EPON') {
        if (opticType == 0) {
          return opticInfo < -24;
        }
        else if (opticType == 1) {
          return opticInfo < -27;
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
      if (1 == IsLAN) {
        setPrograss(1, 128);
        document.getElementById('percent').innerHTML = "30%";
        document.getElementById("frontpic").style.display = 'none';
        if (CfgMode.toUpperCase() == "LNCU") {
          document.getElementById("regResult1").innerHTML = "终端正在获取管理地址。";
        }
        else {
          document.getElementById("regResult1").innerHTML = "正在获取管理IP。";
        }
        return;
      }
      setPrograss(1, 85);
      document.getElementById('percent').innerHTML = "20%";
      document.getElementById("frontpic").style.display = 'none';
      document.getElementById("regResult").style.display = 'none';
      document.getElementById("regResult1Form").style.display = 'block';
      if (CfgMode.toUpperCase() == "LNCU") {
        document.getElementById("regResult1").innerHTML = "终端正在向OLT注册。";
      }
      else {
        document.getElementById("regResult1").innerHTML = "正在注册OLT。";
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

      if (CheckOnlineCnt < 3) {
        CheckOnlineCnt++;
        return;
      }

      CheckOnlineCnt = 0;
      StartCheckStatus++;

      setPrograss(1, 128);
      document.getElementById('percent').innerHTML = "30%";
      document.getElementById("frontpic").style.display = 'none';
      if (CfgMode.toUpperCase() == "LNCU") {
        var LanDesInfo = "终端正在获取管理地址。";
        var PonDesInfo = "OLT注册成功，终端正在获取管理地址。";
        var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
        document.getElementById("regResult1").innerHTML = FinalyDes;
      }
      else {
        document.getElementById("regResult1").innerHTML = "正在获取管理IP。";
      }
      setCookie("StepStatus", "2");
    }

    function setTipsBeforeITMSResult() {
      if ((!IsOpticalNomal()) || (1 == GetLoidAuthStatus && GetDateTimeDiff() > 40)) {
        setPrograss(0, 0);
        document.getElementById('percent').innerHTML = "";
        document.getElementById("frontpic").src = "/images/icon_03.gif";
        document.getElementById("frontpic").style.display = "";
        var LanDesInfo = "注册失败，请检查逻辑ID和密码是否正确。";
        var PonDesInfo = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、逻辑ID和密码是否正确。";
        var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
        document.getElementById("regResult1Form").style.display = 'none';
        document.getElementById("regResult").style.display = 'block';
        document.getElementById("regResult").innerHTML = FinalyDes;
        if (1 != IsLAN) {
          LoidRegResultLog("OLT_Fail");
        }
        setCookie("StepStatus", "4");
      }
      else if (GetStepStatus() == '0') {
        if (GetDateTimeDiff() > 600) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。";
          clearTimeout(timer);
          if (1 != IsLAN) {
            LoidRegResultLog("OLT_TimeOut");
          }
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
        if (GetDateTimeDiff() > 120) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          document.getElementById("regResult1Form").style.display = 'none';
          if (CfgMode.toUpperCase() == "LNCU") {
            for (i = 0; i < Wan.length; i++) {
              var wanServiceList = ["TR069", "TR069_VOIP", "TR069_INTERNET", "TR069_VOIP_INTERNET"];
              if ((Wan[i].ConnectionStatus == "Connected") &&
                  (wanServiceList.indexOf(Wan[i].X_HW_SERVICELIST) >= 0) &&
                  (Wan[i].ConnectionType.toString().toUpperCase().indexOf("BRIDGED") < 0)) {
                document.getElementById("regResult").style.display = 'block';
                document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。";
                LoidRegResultLog("RMS_Timeout");
                break;
              }
              else {
                document.getElementById("regResult").style.display = 'block';
                document.getElementById("regResult").innerHTML = "获取管理地址失败。";
                LoidRegResultLog("RMS_NoIP");
              }
            }
          }
          else {
            document.getElementById("regResult").style.display = 'block';
            document.getElementById("regResult").innerHTML = "注册失败，很抱歉，暂时无法注册，如有疑问，请致电10010，协助解决。";
            LoidRegResultLog("RMS_RegFail");
          }
          clearTimeout(timer);
        }
        else {
          document.getElementById("frontpic").style.display = 'none';

          if (Wan.length == 0) {
            setPrograss(1, 128);
            document.getElementById('percent').innerHTML = "30%";
            if (CfgMode.toUpperCase() == "LNCU") {
              var LanDesInfo = "终端正在获取管理地址。";
              var PonDesInfo = "OLT注册成功，终端正在获取管理地址。";
              var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
              document.getElementById("regResult1").innerHTML = FinalyDes;
            }
            else {
              document.getElementById("regResult1").innerHTML = "正在获取管理IP。";
            }
          }
          else {
            for (i = 0; i < Wan.length; i++) {
              var wanServiceList = ["TR069", "TR069_VOIP", "TR069_INTERNET", "TR069_VOIP_INTERNET"];
              if ((Wan[i].ConnectionStatus == "Connected") &&
                  (wanServiceList.indexOf(Wan[i].X_HW_SERVICELIST) >= 0) &&
                  (Wan[i].ConnectionType.toString().toUpperCase().indexOf("BRIDGED") < 0)) {
                setPrograss(1, 170);
                document.getElementById('percent').innerHTML = "40%";
                if (CfgMode.toUpperCase() == "LNCU") {
                  document.getElementById("regResult1").innerHTML = "终端获取管理地址成功，正在注册RMS管理平台。";
                }
                else {
                  document.getElementById("regResult1").innerHTML = "已获得管理IP，正在连接RMS。";
                }
                break;
              }
              else {
                setPrograss(1, 128);
                document.getElementById('percent').innerHTML = "30%";
                CheckDetailInfo = 1;
                if (CfgMode.toUpperCase() == "LNCU") {
                  var LanDesInfo = "终端正在获取管理地址。";
                  var PonDesInfo = "OLT注册成功，终端正在获取管理地址。";
                  var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
                  document.getElementById("regResult1").innerHTML = FinalyDes;
                }
                else {
                  document.getElementById("regResult1").innerHTML = "正在获取管理IP。";
                }
              }
            }
          }
        }

      }
      else if (GetStepStatus() == '3') {
        if (GetDateTimeDiff() > 300) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          var LanDesInfo = "注册失败，请检查逻辑ID和密码是否正确。";
          var PonDesInfo = "在OLT上注册失败，请检查逻辑ID和密码是否正确。";
          var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          document.getElementById("regResult").innerHTML = FinalyDes;
          if (1 != IsLAN) {
            LoidRegResultLog("OLT_Fail");
          }
          clearTimeout(timer);
        }
        else {
          StartRegStatus();
          if (IsOntOnline == 1) {
            CheckOnlineCnt = 0;
            setCookie("StepStatus", "0");
          }
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
    function getRegSuccessTips() {
      var strProvisioning = Infos.ProvisioningCode.split(',');
      var strNewProvisioning = '';
      var strNum;

      LoidRegResultLog("RMS_CfgSuccess");
      if ("" == Infos.ProvisioningCode) {
        return "注册成功，下发业务成功。";
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
        return "ITMS平台数据下发成功，共下发了" + strNewProvisioning + strNum + "个业务。";
      }
    }

    function IsRegTimesToLimits() {
      return parseInt(Infos.Times) >= parseInt(Infos.Limits);
    }

    function LoadFrame() {
      CheckWanInfo();
      LoadFrameInfo(2000);
    }

    function LoadFrameInfo(time) {
      /* 启动超时定时器 */
      setRefreshInterval(time);

      if (((1 != IsOntOnline) || (0 != parseInt(Infos.InformStatus)))) {
        Infos.Status = 99;
      }

      if (Infos != null) {

        if (parseInt(Infos.Status) == 0) {
          StartCheckStatus++;
          if (parseInt(Infos.Result) == 99) {
            setPrograss(1, 213);
            document.getElementById('percent').innerHTML = "50%";
            document.getElementById("frontpic").style.display = 'none';
            if (GetDateTimeDiff() > 300) {
              document.getElementById("regResult1").innerHTML = "注册RMS超过300秒，请耐心等待或者返回重试。";
              return;
            }

            if (CfgMode.toUpperCase() == "LNCU") {
              document.getElementById("regResult1").innerHTML = "终端注册RMS管理平台成功，等待RMS平台下发业务数据。";
            }
            else {
              document.getElementById("regResult1").innerHTML = "注册成功，等待RMS平台下发业务数据。";
            }
          }
          else if (parseInt(Infos.Result) == 0) {
            setPrograss(1, 255);
            document.getElementById('percent').innerHTML = "60%";
            document.getElementById("frontpic").style.display = 'none';
            if (GetDateTimeDiff() > 300) {
              document.getElementById("regResult1").innerHTML = "RMS下发业务超过300秒，请耐心等待或者返回重试。";
              return;
            }

            if (CfgMode.toUpperCase() == "LNCU") {
              var LanDesInfo = "RMS正在下发业务，请不要断电和插拔网线。";
              var PonDesInfo = "RMS正在下发业务，请不要断电和插拔光纤。";
              var FinalyDes = (1 == IsLAN) ? LanDesInfo : PonDesInfo;
              document.getElementById("regResult1").innerHTML = FinalyDes;
            }
            else {
              document.getElementById("regResult1").innerHTML = "RMS平台正在下发业务数据，请勿断电或拔线。";
            }
          }
          else if (parseInt(Infos.Result) == 1) {
            setPrograss(1, 425);
            document.getElementById('percent').innerHTML = "100%";
            document.getElementById("frontpic").style.display = 'none';
            if (CfgMode.toUpperCase() == "LNCU") {
              document.getElementById("regResult1").innerHTML = "注册全部完成，业务下发配置成功，欢迎使用辽宁联通的通信业务。";
            }
            else {
              document.getElementById("regResult1").innerHTML = "注册成功，下发业务成功。";
            }
            LoidRegResultLog("RMS_CfgSuccess");
            clearTimeout(timer);
            return;
          }
          else {
            setPrograss(0, 0);
            document.getElementById('percent').innerHTML = "";
            document.getElementById("frontpic").src = "/images/icon_04.gif";
            document.getElementById("frontpic").style.display = "";
            document.getElementById("regResult1Form").style.display = 'none';
            document.getElementById("regResult").style.display = 'block';
            document.getElementById("regResult").innerHTML = "注册成功，下发业务失败，请联系10010号。";
            LoidRegResultLog("RMS_CfgFail");
          }
        }
        else if (parseInt(Infos.Status) == 1) {
          StartCheckStatus++;
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          LoidRegResultLog("RMS_RegFail");
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "密码不对，注册失败，请联系10010。";
          }
          else {
            document.getElementById("regResult").innerHTML = "密码不对，注册失败，请" + '<a href="/loidreg.asp" style="color:blue;font-size:18px;font-weight:bold;">重试</a>' + "（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }

        }
        else if (parseInt(Infos.Status) == 2) {
          StartCheckStatus++;
          setPrograss(0, 0);
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          document.getElementById('percent').innerHTML = "";
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          LoidRegResultLog("RMS_RegFail");
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "逻辑ID不对，注册失败，请联系10010。";
          }
          else {
            document.getElementById("regResult").innerHTML = "逻辑ID不对，注册失败，请" + '<a href="/loidreg.asp" style="color:blue;font-size:18px;font-weight:bold;">重试</a>' + "（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }

        }
        else if (parseInt(Infos.Status) == 3) {
          StartCheckStatus++;
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          LoidRegResultLog("RMS_RegFail");
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          if (IsRegTimesToLimits()) {
            document.getElementById("regResult").innerHTML = "逻辑ID与密码不匹配！注册失败，请联系10010。";
          }
          else {
            document.getElementById("regResult").innerHTML = "逻辑ID与密码不匹配！请" + '<a href="/loidreg.asp" style="color:blue;font-size:18px;font-weight:bold;">重试</a>' + "（剩余尝试次数：" + (parseInt(Infos.Limits) - parseInt(Infos.Times)) + "）。";
          }

        }
        else if (parseInt(Infos.Status) == 4) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_03.gif";
          document.getElementById("frontpic").style.display = "";
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          document.getElementById("regResult").innerHTML = "注册超时！请检查线路后重试。";
          LoidRegResultLog("RMS_Timeout");
        }
        else if (parseInt(Infos.Status) == 5) {
          setPrograss(0, 0);
          document.getElementById('percent').innerHTML = "";
          document.getElementById("frontpic").src = "/images/icon_04.gif";
          document.getElementById("frontpic").style.display = "";
          document.getElementById("regResult1Form").style.display = 'none';
          document.getElementById("regResult").style.display = 'block';
          document.getElementById("regResult").innerHTML = "已经注册成功，无需重新注册。";
          clearTimeout(timer);
          LoidRegResultLog("RMS_RegRepeat");
          return;

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
        window.location = "/cu.html";
      }
      else {
        window.location = "/loidreg.asp";
      }
    }

  </script>
</head>

<body onLoad="LoadFrame();" style="font-size: 14px;">
  <form>
    <div align="center">
      <TABLE cellSpacing="0" cellPadding="0" align="center" border="0" style="font-size: 14px;">
        <TBODY>
          <TR>
            <TABLE cellSpacing="0" cellPadding="0" align="middle" border="0" style="font-size: 14px;">
              <TBODY>
                <TR>
                  <script type="text/javascript" language="javascript">
                    if (IsMaintWan == 1) {
                      var starIdx = window.location.href.indexOf('://');
                      var subAddr = window.location.href.substr(starIdx + 3);
                      var br0Ip = subAddr.substring(0, subAddr.indexOf('/'));
                    }
                    document.write('<TD align="center" style="background-image:url(/images/background.gif); background-repeat:no-repeat;width:1066px;height:600px;">');
                  </script>
                  <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0" style="font-size: 14px;">
                    <TR>
                      <TD align="right" style="padding-right:50px; padding-top:0px">
                        <script language="javascript">
                          document.write('<A style="text-decoration: none; color:#b2b2b2; font-size: 16px;" href="http://' + br0Ip + '">返回登录页面</A>');
                        </script>
                      </TD>
                    </TR>
                  </TABLE>

                  <TABLE cellSpacing="0" cellPadding="0" width="96%" height="7%" border="0" style="font-size: 14px;">
                    <TR>
                      <TD></TD>
                    </TR>
                  </TABLE>

                  <br>
                  <TABLE cellSpacing="0" cellPadding="0" width="576" border="0" height="65%">
                    <TR>
                      <TD colspan="2" align="center">
                        <div id="percent" style="padding-top:40px; color: #b2b2b2; "><span
                            style="font-family: '微软雅黑';font-size:15px;"></span></div>
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
                      <TD colspan="2">
                        <img id="frontpic" width="84" height="84" style="display:none; float:left;" />
                        <span id="regResult1Form" style="padding:10px 0 0 45px; float:left; width:440px;">
                          <font id="regResult1"
                            style="font-family: '微软雅黑';font-size:16px; color:#000000;margin-left: 30px;"></font>
                        </span>
                        <span style="padding:14px 0 0 45px; float:left; width:440px;">
                          <font id="regResult" style="font-family: '微软雅黑';font-size:21px; color:#000000;"></font>
                        </span>
                      </TD>
                    </TR>

                    <TR>
                      <TD colspan="1" align="center" 　height="10">
                        <img src="/images/back.gif" style="cursor:pointer;" value="" onClick="JumpTo();" />
                      </TD>
                    </TR>
                    <TR>
                    </TR>
                    <TR>
                      <TD align="left" colSpan="2" height="130"></TD>
                    </TR>
                  </TABLE>

                  <TABLE cellSpacing="0" cellPadding="0" width="96%" height="8%" border="0" style="font-size: 14px;">
                    <TR>
                      <TD></TD>
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