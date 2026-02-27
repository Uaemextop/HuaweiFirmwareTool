<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1" />
  <meta http-equiv="Pragma" content="no-cache" />
  <script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
  <script type="text/javascript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <title></title>
  <style type="text/css">
    body {
      margin-top: 0px;
    }

    div#mainpage {
      width: 1066px;
      height: 600px;
      background-repeat: no-repeat;
      margin: 0px auto;
      background-image: url(/images/background.gif);
    }

    div#mainpage div#prefresh {
      display: block;
    }

    div#devicelogo {
      float: left;
      position: relative;
      margin-top: 230px;
      margin-left: 60px;
    }

    #devicelogo .DeviceInfo {
      position: absolute;
      width: 175px;
      color: #FFFFFF;
      font-weight: bold;
      font-size: 20px;
      font-family: "微软雅黑";

    }

    #devicelogo .DeviceName {
      position: absolute;
      top: 26px;
      width: 175px;
      color: #FFFFFF;
      font-weight: bold;
      font-size: 40px;
      font-family: Arial;
      text-align: center;
    }

    #devicelogo .DeviceNameRe {
      position: absolute;
      top: 53px;
      width: 175px;
      color: #FFFFFF;
      font-weight: bold;
      font-size: 40px;
      font-family: Arial;
      text-align: center;
      transform: rotateX(180deg);
      -webkit-transform: rotateX(180deg);
      opacity: 0.2;
      filter: alpha(opacity=20) FlipV;
    }

    div#navigation {
      margin-left: 0px;

    }

    #prebutton div {
      float: left;
    }

    .statuslink {
      margin: 45px 0 0 102px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initstatus.gif);
    }

    a.statuslink:hover {
      margin: 1px -23px 0 79px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overstatus.gif);
    }

    .basiclink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initbasic.gif);
    }

    a.basiclink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overbasic.gif);
    }

    .advancelink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initadvance.gif);
    }

    a.advancelink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overadvance.gif);
    }

    .decivelink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initdevice.gif);
    }

    a.decivelink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overdevice.gif);
    }

    .quicklink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initquick.gif);
    }

    a.quicklink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overquick.gif);
    }

    .helplink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/inithelp.gif);
    }

    a.helplink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overhelp.gif);
    }

    .quitlink {
      margin: 45px 0 0 35px;
      display: block;
      height: 119px;
      width: 87px;
      background-image: url(/images/initquit.gif);
    }

    a.quitlink:hover {
      margin: 1px -23px 0 12px;
      height: 160px;
      width: 133px;
      background-image: url(/images/overquit.gif);
    }

    div#mainpage div#devicelist {
      width: 100%;
      height: 530px;
    }

    div#mainpage div#devicelist div#navigation p {
      margin-top: 30px;
    }

    div#mainpage div#devicelist div#navigation p input {
      background: none;
      border: none;
      font-weight: bold;
      color: #FFFFFF;

      height: 22px;
    }

    div#mainpage div#devicelist div#navigation p a {
      font-size: 14px;
      text-decoration: none;
      font-weight: bold;
      color: #FFFFFF;
    }

    div#mainpage div#devicelist div#navigation p a:hover {
      color: #FF9900;
    }
  </style>

  <script language="JavaScript" type="text/javascript">
    function GetAccessMode() {
      var accModes = new Array(["not initial", "NOT INITIAL"], ["gpon", "GPON"], ["epon", "EPON"],
        ["10g-gpon", "10G GPON"], ["Symmetric 10g-gpon", "10G GPON"], ["Asymmetric 10g-epon", "10G EPON"],
        ["Symmetric 10g-epon", "10G EPON"], ["ge", "LAN"]);

      var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';

      var i = 0;

      for (; i < accModes.length; i++) {
        if (ontPonMode == accModes[i][0])
          return accModes[i][1];
      }

      return "--";
    }
    var SingWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_SINGLE_WLAN);%>';
    var DoubleWlanFlag = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_DOUBLE_WLAN);%>';
    var devicename = '<%GetAspPoductName();%>';
    var curUserType = '<%HW_WEB_GetUserType();%>';
    document.title = devicename;
    var UpgradeFlag = 0;
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    if (CfgMode.toUpperCase() == 'LNCU') {
      window.location = "/CtcApp/lnpreindex.asp";
    }
    var DeviceInfo = "中国联通FTTH终端";
    var ontPonMode = GetAccessMode();
    var TopoInfoNumEx = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_Topo.X_HW_EthNum);%>';
    var TopoInfoNum = TopoInfoNumEx;
    if (ontPonMode == "LAN") {
      TopoInfoNum = TopoInfoNumEx - 1;
    }
    function stPhyInterface(Domain, InterfaceID) {
      this.Domain = Domain;
    }
    var AllPhyInterface = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.Services.VoiceService.1.PhyInterface.{i}, InterfaceID, stPhyInterface);%>;
    var VoiceNum = AllPhyInterface.length - 1;

    if (-1 == ontPonMode.toUpperCase().indexOf("PON")) {
      DeviceInfo = "中国联通家庭网关";
    }

    function StatusGuide() {
      setCookie("MenuJumpIndex", "0");
      window.location = "/index.asp";
    }

    function BasicGuide() {
      setCookie("MenuJumpIndex", "1");
      window.location = "/index.asp";
    }

    function AdvanceGuide() {
      setCookie("MenuJumpIndex", "2");
      window.location = "/index.asp";
    }

    function DeviceGuide() {
      setCookie("MenuJumpIndex", "3");
      window.location = "/index.asp";
    }

    function QuickGuide() {
      setCookie("MenuJumpIndex", "4");
      window.location = "/index.asp";
    }

    function HelpGuide() {
      setCookie("MenuJumpIndex", "5");
      window.location = "/index.asp";
    }

    function LogoutGuide() {
      setCookie("MenuJumpIndex", "0");
      LogoutWithPara("", "/CU.html", false, curUserType);
    }
  </script>
</head>

<body>
  <div id="mainpage">
    <div id="devicelist">
      <div id="navigation" style="width:100%; padding-top:195px">
        <div id="prebutton">
          <div>
            <a id="statuslink" name="statuslink" href="#" class="statuslink" onclick="StatusGuide();"></a>
          </div>
          <div>
            <a id="basiclink" name="basiclink" href="#" class="basiclink" onclick="BasicGuide();"></a>
          </div>
          <div>
            <a id="advancelink" name="advancelink" href="#" class="advancelink" onclick="AdvanceGuide();"></a>
          </div>
          <div>
            <a id="decivelink" name="decivelink" href="#" class="decivelink" onclick="DeviceGuide();"></a>
          </div>
          <div>
            <a id="quicklink" name="quicklink" href="#" class="quicklink" onclick="QuickGuide();"></a>
          </div>
          <div>
            <a id="helplink" href="#" class="helplink" onclick="HelpGuide();"></a>
          </div>
          <div>
            <a id="quitlink" name="quitlink" href="#" class="quitlink" onclick="LogoutGuide();"></a>
          </div>
        </div>
      </div>
    </div>
    <div style="margin-top:31px; margin-left:365px;">
      <span style="color:#b2b2b2;font-size:12px;">
        <script language="JavaScript" type="text/javascript">
          var WifiMode = "";
          if (SingWlanFlag == "1") {
            WifiMode = "+WiFi(2.4G)";
          } else if (DoubleWlanFlag == "1") {
            WifiMode = "+WiFi(2.4G + 5G)";
          }
          document.write(DeviceInfo + "&nbsp" + ontPonMode.toUpperCase() + "/" + TopoInfoNum + "+" + VoiceNum + WifiMode);
        </script>
    </div>
</body>

</html>