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
    div#mainpage {
      width: 850px;
      height: 572px;
      background-repeat: no-repeat;
      margin: 0px auto;
      background-image: url(/images/adminbg.gif);
    }

    div#mainpage div#prefresh {
      display: none;
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
      -webkit-transform: scaleY(-1);
      -moz-transform: scaleY(-1);
      -ms-transform: scaleY(-1);
      -o-transform: scaleY(-1);
      transform: scaleY(-1);
      opacity: 0.2;
      filter: alpha(opacity=20);
    }

    div#navigation {
      margin-left: 300px;

    }

    .statuslink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initstatus.gif);
    }

    a.statuslink:hover {
      background-image: url(/images/overstatus.gif);
    }

    .basiclink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initbasic.gif);
    }

    a.basiclink:hover {
      background-image: url(/images/overbasic.gif);
    }

    .advancelink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initadvance.gif);
    }

    a.advancelink:hover {
      background-image: url(/images/overadvance.gif);
    }

    .decivelink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initdevice.gif);
    }

    a.decivelink:hover {
      background-image: url(/images/overdevice.gif);
    }

    .quicklink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initquick.gif);
    }

    a.quicklink:hover {
      background-image: url(/images/overquick.gif);
    }

    .helplink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/inithelp.gif);
    }

    a.helplink:hover {
      background-image: url(/images/overhelp.gif);
    }

    .quitlink {
      display: block;
      height: 55px;
      width: 119px;
      background-image: url(/images/initquit.gif);
    }

    a.quitlink:hover {
      background-image: url(/images/overquit.gif);
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
    var devicename = '<%GetAspPoductName();%>';
    var curUserType = '<%HW_WEB_GetUserType();%>';
    document.title = devicename;
    var UpgradeFlag = 0;
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    if (CfgMode.toUpperCase() == 'LNCU') {
      window.location = "/CtcApp/lnpreindex.asp";
    }
    var DeviceInfo = "中国联通FTTH终端";
    var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
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
      <div id="devicelogo">
        <span class="DeviceInfo">
          <script language="JavaScript" type="text/javascript">
            document.write(DeviceInfo)
          </script>
        </span>
        <br>
        <span class="DeviceName">
          <script language="JavaScript" type="text/javascript">
            document.write(devicename);
          </script>
        </span>
        <span class="DeviceNameRe">
          <script language="JavaScript" type="text/javascript">
            document.write(devicename);
          </script>
        </span>
      </div>
      <div id="navigation" style="width:400px; padding-top:70px">
        <table width="100%" id="prebutton">
          <tr>
            <table width="100%">
              <tr>
                <td width="250px"></td>
                <td><a id="statuslink" name="statuslink" href="#" class="statuslink" onclick="StatusGuide();"></a></td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="180px"></td>
                <td><a id="basiclink" name="basiclink" href="#" class="basiclink" onclick="BasicGuide();"></a></td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="110px"></td>
                <td><a id="advancelink" name="advancelink" href="#" class="advancelink" onclick="AdvanceGuide();"></a>
                </td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="40px"></td>
                <td><a id="decivelink" name="decivelink" href="#" class="decivelink" onclick="DeviceGuide();"></a></td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="110px"></td>
                <td><a id="quicklink" name="quicklink" href="#" class="quicklink" onclick="QuickGuide();"></a></td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="180px"></td>
                <td><a id="helplink" href="#" class="helplink" onclick="HelpGuide();"></a></td>
              </tr>
              <table>
          </tr>
          <tr>
            <table width="100%">
              <tr>
                <td width="250px"></td>
                <td><a id="quitlink" name="quitlink" href="#" class="quitlink" onclick="LogoutGuide();"></a></td>
              </tr>
              <table>
          </tr>
        </table>
      </div>
    </div>
    <div style="position:absolute; top:550px;">
      <table border="0" cellpadding="0" cellspacing="0" width="100%" align="left" style="margin-left:15px;">
        <tr>
          <td>
            <img src="../images/icon_02.gif" width="10" height="10" style="margin-left:20px" />
            <font style="color:#FFFFFF;font-size:12px">网上营业厅&nbsp;</font>
            <a href="http://www.10010.com" target="_blank"
              style="text-decoration:none;color:#FFFFFF;font-size:12px">www.10010.com</a>
            <img src="../images/icon_02.gif" width="10" height="10" style="margin-left:1px" />
            <font style="color:#FFFFFF;font-size:12px">客服热线10010&nbsp;&nbsp;充值专线10011</font>
          </td>
        </tr>
      </table>
    </div>
    <div id="prefresh">
      <iframe frameborder="0" height="100%" marginheight="0" marginwidth="0" scrolling="no" src="/refresh.asp"
        width="100%"></iframe>
    </div>
  </div>
</body>

</html>