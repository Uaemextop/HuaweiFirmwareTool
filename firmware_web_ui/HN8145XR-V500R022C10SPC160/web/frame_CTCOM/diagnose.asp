<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <link href="/Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>" media="all" rel="stylesheet" />
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Cache-Control" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title></title>

  <script language="JavaScript"
    src="/../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
  <script type="text/javascript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <script language="JavaScript" type="text/javascript">

    var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';
    var Var_DefaultLang = '<%HW_WEB_GetCurrentLanguage();%>';
    var Language = "chinese";
    document.title = ProductName;

    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    var opticInfo = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic.RxPower);%>';
    function stResult(domain, Result) {
      this.domain = domain;
      this.Result = Result;
    }

    var StatusPrompt = new Array();
    var TotalTestResult = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.VSPA.TotalTestResult.{i}, Result, stResult);%>;
    var TestState = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.VSPA.TotalTest.TestState);%>';
    var VoipSupport = '<%HW_WEB_GetFeatureSupport(HW_VSPA_FEATURE_VOIP);%>';
    var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>'
    var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';

    var interval = "";
    function WanPPPDiagnose(domain, ConnectionTrigger, Status, Mode, IPAddress, ConnectionControl, ServiceList, ExServiceList) {
      this.domain = domain;
      this.ConnectionTrigger = ConnectionTrigger;

      if (parseInt(ConnectionControl, 10) == 0xFFFFFFFF) {
        this.ConnectionControl = 0;
      }
      else {
        this.ConnectionControl = ConnectionControl;
      }

      if ((Status.toUpperCase() == "CONNECTING") && (this.ConnectionControl == "0") && (ConnectionTrigger == "Manual")) {
        this.Status = "Disconnected";
      }
      else {
        this.Status = Status;
      }

      this.Mode = Mode;
      this.IPMode = 'PPPoE';
      this.IPAddress = IPAddress;
      this.ServiceList = (ExServiceList.length == 0) ? ServiceList.toUpperCase() : ExServiceList.toUpperCase();
    }

    var PPPWanList = <%HW_WEB_GetSpecParaArryByDomain(HW_WEB_SpecParaArrayPPPWAN, InternetGatewayDevice.WANDevice.1.WANConnectionDevice.{i}.WANPPPConnection.{i}, ConnectionTrigger|ConnectionStatus|ConnectionType|ExternalIPAddress|X_HW_ConnectionControl|X_HW_SERVICELIST|X_HW_ExServiceList, WanPPPDiagnose);%>;

    function GetInternetWanstate() {
      var Currentwan = null;

      for (var i = 0; i < PPPWanList.length - 1; i++) {

        if (('IP_Routed' == PPPWanList[i].Mode)
          && ('PPPoE' == PPPWanList[i].IPMode)
          && (PPPWanList[i].ServiceList.toString().toUpperCase().indexOf("INTERNET") >= 0)) {
          Currentwan = PPPWanList[i];
          break;
        }
      }

      if (null == Currentwan) {
        return 0;

      }

      if (("Connected" == Currentwan.Status) && ('' != Currentwan.IPAddress)) {
        return 1;
      }

      return 2;
    }

    var wanstatusinfo = GetInternetWanstate();

    function IsOpticalNomal() {
      return opticInfo != "--";
    }

    function Oninternetstatus() {
      if (0 == wanstatusinfo) {
        getElement('internetsatus').innerHTML = "无上网业务";
      }
      else if (1 == wanstatusinfo) {
        getElement('internetsatus').innerHTML = "业务正常";
      }
      else if (2 == wanstatusinfo) {
        getElement('internetsatus').innerHTML = "业务不正常（故障代码602）";
        StatusPrompt.push("请检查PPPOE拨号的账号和密码是否正确");
      }

    }

    function Ongatewaystatus() {
      if (!IsOpticalNomal()) {
        if (1 != IsLAN) {
          getElement('gatewaystatus').innerHTML = "1、请检查光纤连接是否正常<br>2、如果光纤连接正常，请关闭家庭网关电源，重新启动<br>3、如果故障依旧，请拨打10000咨询";
        }
        else {
          getElement('gatewaystatus').innerHTML = "1、请关闭家庭网关电源，重新启动<br>2、如果故障依旧，请拨打10000咨询";
        }
      }
      else {
        var strinfo = "";
        var strindex = 1;
        StatusPrompt.push("如果故障依旧，请拨打10000咨询");
        for (var i = 0; i < StatusPrompt.length; i++) {
          strinfo += strindex + "、";
          strinfo += StatusPrompt[i];
          strinfo += "<br>"
          strindex++;
        }
        if (1 == wanstatusinfo) {
          getElement('gatewaystatus').innerHTML = "业务正常，无需处理";
        }
        else {
          getElement('gatewaystatus').innerHTML = strinfo;
        }

      }

    }

    function Ondiagresult() {
      if (1 == VoipSupport) {
        setCookie("VoipTestState", "Requested");
        setDisable('diagnosed', 1);
        var Form = new webSubmitForm();
        Form.addParameter('x.TestState', "Requested");
        Form.addParameter('x.X_HW_Token', getAuthToken());
        Form.setAction('SetTestState.cgi?x=InternetGatewayDevice.X_HW_DEBUG.VSPA.TotalTest'
          + '&RequestFile=diagnose.asp');
        Form.submit();
      }
      else {
        setCookie("internetstatusinfo", "startrefresh");
        window.location.href = "/diagnose.asp";
      }
    }

    function Ondiagnosed() {
      setDisable('diagnosed', 1);
      document.getElementById('diagnosed_result').style.display = 'none';
      getElement('reportloading').innerHTML = '<B><FONT color=red>正在进行业务诊断，请稍后...' + '</FONT><B>';
      setTimeout('Ondiagresult()', 3000);
    }

    function VoipGatewayStatusInof() {
      var inormalNUM = 0;
      var Index = 1;
      var iCountPort = 0;
      var iErrorCount = 0;
      var strPort = 0;
      var strLOOP_ABNORMAL = 0;
      var errorcode;
      var strConfigurationInfo = 0;
      var iCountConfigurationPort = 0;

      for (Index; Index < TotalTestResult.length; Index++) {
        if (TotalTestResult[Index - 1].Result == 0) {
          inormalNUM++;
          continue;
        }
        else if (2 == TotalTestResult[Index - 1].Result) {
          iCountConfigurationPort++;
          if (iCountConfigurationPort > 1) {
            strConfigurationInfo += ',';
            strConfigurationInfo += Index;
          }
          else {
            strConfigurationInfo += Index;
          }
          errorcode = "607";
        }
        else if (4 == TotalTestResult[Index - 1].Result) {
          iCountPort++;
          if (iCountPort > 1) {
            strPort += ',';
            strPort += Index;
          }
          else {
            strPort += Index;
          }

          errorcode = "608";
        }
        else if (5 == TotalTestResult[Index - 1].Result) {
          iErrorCount++;
          if (iErrorCount > 1) {
            strLOOP_ABNORMAL += ',';
            strLOOP_ABNORMAL += Index;
          }
          else {
            strLOOP_ABNORMAL += Index;
          }

          errorcode = "699";
        }
        else {
          errorcode = "600";
        }

      }

      if (inormalNUM == TotalTestResult.length - 1) {
        getElement('voicestatus').innerHTML = "业务正常";
      }
      else {
        if (0 != iCountPort) {
          var portpormpt = strPort + "语音端口注册失败";

          StatusPrompt.push(portpormpt);
        }

        if (0 != iErrorCount) {
          var ErrorCountpormpt = "请检查" + strLOOP_ABNORMAL + "语音端口连接是否正常";
          StatusPrompt.push(ErrorCountpormpt);
        }

        if (0 != iCountConfigurationPort) {
          var ConfigurationPortpormpt = strConfigurationInfo + "语音端口业务未配置";
          StatusPrompt.push(ConfigurationPortpormpt);
        }

        getElement('voicestatus').innerHTML = "业务不正常（故障代码" + errorcode + "）";

      }

      if (!IsOpticalNomal()) {
        if (1 != IsLAN) {
          getElement('gatewaystatus').innerHTML = "1、请检查光纤连接是否正常<br>2、如果光纤连接正常，请关闭家庭网关电源，重新启动<br>3、如果故障依旧，请拨打10000咨询";
        }
        else {
          getElement('gatewaystatus').innerHTML = "1、请关闭家庭网关电源，重新启动<br>2、如果故障依旧，请拨打10000咨询";
        }
      }
      else {
        var strinfo = "";
        var strindex = 1;
        StatusPrompt.push("如果故障依旧，请拨打10000咨询");
        for (var i = 0; i < StatusPrompt.length; i++) {
          strinfo += strindex + "、";
          strinfo += StatusPrompt[i];
          strinfo += "<br>"
          strindex++;
        }
        if ((inormalNUM == TotalTestResult.length - 1) && (1 == wanstatusinfo)) {
          getElement('gatewaystatus').innerHTML = "业务正常，无需处理";
        }
        else {
          getElement('gatewaystatus').innerHTML = strinfo;
        }

      }
    }

    function requestCgiResult() {
      window.location.href = "/diagnose.asp";
    }

    function LoadFrame() {
      if (1 == VoipSupport) {
        var voicestatusinfo = getCookie("VoipTestState");
        if ('Requested' == TestState) {
          setDisable('diagnosed', 1);
          getElement('reportloading').innerHTML = '<B><FONT color=red>正在进行业务诊断，请稍后...' + '</FONT><B>';
          interval = setInterval('requestCgiResult()', 1000);
        }
        else if (('Complete' == TestState) && ("Requested" == voicestatusinfo)) {
          setCookie("VoipTestState", "Complete");
          setDisable('diagnosed', 0);
          getElement('reportloading').innerHTML = '';
          document.getElementById('diagnosed_result').style.display = '';
          Oninternetstatus();
          VoipGatewayStatusInof();
        }
      }
      else {
        var bbspstatusinfo = getCookie("internetstatusinfo");
        if ("startrefresh" == bbspstatusinfo) {
          setCookie("internetstatusinfo", "none");
          Oninternetstatus();
          Ongatewaystatus();
          getElement('voicestatus').innerHTML = "无电话业务";
          document.getElementById('diagnosed_result').style.display = '';
          getElement('reportloading').innerHTML = '';
        }
      }

    }
  </script>
</head>

<body onload="LoadFrame();">
  <div class="diagnosedlogo">
    <div id="logo" style="width:100%;">
      <table width="100%" border="0" cellspacing="0" cellpadding="0" style="position:relative;top:75px;">
        <tr>
          <td align="right" style="color:#ffffff;">不能上网？电话不通？电视看不了？别着急，请进行 &nbsp;&nbsp;</td>
          <td align="left">
            <input type="submit" style="background:#f7a037;color:#ffffff;;width:240px;" id="diagnosed" name="diagnosed"
              onClick="Ondiagnosed();" value="一键诊断">
          </td>
        </tr>
      </table>
      <div name="reportloading" id="reportloading" style="position:relative;top:105px;"></div>
      <table id="diagnosed_result" width="100%" border="0" cellspacing="0" cellpadding="0"
        style="position:relative;top:105px;display: none">
        <tr>
          <td width="30"></td>
          <td align="left" width="347"><img width="21" height="17" src="/images/diagnosed_result.gif" />&nbsp;&nbsp;诊断结果
            <table width="100%" border="0" cellspacing="0" cellpadding="0"
              style="height:222px; width:347px;background: url('/images/background.gif') no-repeat center;">
              <tr>
                <td width="10"></td>
                <td width="10"><img width="43" height="37" src="/images/internet.gif" /></td>
                <td width="30" align="center">上网</td>
                <td align="left">
                  <table width="80%" height="45" border="0" cellspacing="0" cellpadding="0"
                    style="background-color: #e8e8e8;margin-left:30px;">
                    <tr>
                      <td id="internetsatus"></td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td width="10"></td>
                <td width="10"><img width="43" height="36" src="/images/call.gif" /></td>
                <td width="30" align="center">电话</td>
                <td align="left">
                  <table width="80%" height="45" border="0" cellspacing="0" cellpadding="0"
                    style="background-color: #e8e8e8;margin-left:30px;">
                    <tr>
                      <td id="voicestatus"></td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
          <td align="left" width="347"><img width="20" height="16" src="/images/setting.gif" />&nbsp;&nbsp;请您处理
            <table width="100%" border="0" cellspacing="0" cellpadding="0"
              style="height:222px; width:347px;background: url('/images/background.gif') no-repeat center;">
              <tr>
                <td width="10"></td>
                <td width="10"><img width="43" height="38" src="/images/gateway.gif" /></td>
                <td width="60" align="center">家庭网关（电信猫）</td>
                <td align="left">
                  <table width="90%" height="100" border="0" cellspacing="0" cellpadding="0"
                    style="background-color: #e8e8e8;">
                    <tr>
                      <td id="gatewaystatus"></td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
      <table width="100%" border="0" cellspacing="0" cellpadding="0" style="position:relative;top:120px;">
        <tr>
          <td width="30"></td>
          <td align="left">使用说明 > >
          </td>
        </tr>
        <tr>
          <td width="30"></td>
          <td align="left">1、本页面会在上网业务不正常时自动弹出，您也可以登录http:192.168.1.1/diagnose.asp进行语音业务诊断。
          </td>
        </tr>
        <tr>
          <td width="30"></td>
          <td align="left">2、默认对所有可能开通的业务都进行诊断，如您未开通相关业务，请忽略相应的诊断提示。
          </td>
        </tr>
        <tr>
          <td width="30"></td>
          <td align="left">3、您还可通过以下方式进行自助服务，网络故障，轻松搞定！
          </td>
        </tr>
        <tr>
          <td width="30"></td>
          <td align="left">
            扫描下方二维码，安装易信客户端，搜索并关注公众号：“电信宽带小帮手”&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;扫描下方二维码，安装手机版10000管家
          </td>
        </tr>
        <tr>
          <td width="30"></td>
          <td align="left">
            <img width="71" height="63" src="/images/scancode1.gif" />
            <img style="margin-left:360px;" width="71" height="59" src="/images/scancode2.gif" />
          </td>
        </tr>
      </table>
      <table width="100%" height="20" border="0" cellspacing="0" cellpadding="0"
        style="position:absolute;left:0px;top:583px;background-color: #325981;">
        <tr>
          <td></td>
        </tr>
      </table>
    </div>
  </div>
</body>

</html>