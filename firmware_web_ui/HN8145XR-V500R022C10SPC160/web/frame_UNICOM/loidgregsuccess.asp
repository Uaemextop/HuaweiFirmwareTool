<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <title>中国联通</title>
</head>
<style>
  .input_time {
    border: 0px;
  }
</style>
<script language="javascript">
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';

  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
  var loadedcolor = 'orange';
  var unloadedcolor = 'white';
  var bordercolor = 'orange';
  var barheight = 15;
  var barwidth = 300;
  var ns4 = (document.layers) ? true : false;
  var ie4 = (document.all) ? true : false;
  var PBouter;
  var PBdone;
  var PBbckgnd;
  var txt = '';
  var CfgMode = '<%HW_WEB_GetCfgMode();%>';

  function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
  if (null != stResultInfos && null != stResultInfos[0]) {
    var SuccInfos = stResultInfos[0];
  }
  else {
    var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
    var SuccInfos = stResultInfos[0];
  }

  txt += getLayerStr(ns4, barheight, barwidth, bordercolor, barheight, unloadedcolor, loadedcolor);

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

  function LoadFrame() {
    if ((parseInt(SuccInfos.Status) == 0) && (parseInt(SuccInfos.Result) == 1)) {
      document.getElementById("frontpic").src = "/images/icon_04.gif";
      document.getElementById("frontpic").style.display = "";
      document.getElementById('regsuccshow').style.display = "";
      document.getElementById("regResult").innerHTML = "已经注册成功，无需重新注册。";
    }
    else {
      window.location = "/login.asp";
    }
  }

  function JumpTo() {
    window.location = "/login.asp";
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div id="regsuccshow"
      style="display:none; background-image:url(/images/background.gif); width:1066px; height:600px; background-repeat: no-repeat; margin: 0px auto;">
      <TABLE cellSpacing="0" cellPadding="0" width=1066px height=600px border="0">
        <TR>
          <TD>
            <TABLE cellSpacing="0" cellPadding="0" width="100%" height="25%" border="0">
              <TR>
                <TD>
                </TD>
              </TR>
            </TABLE>
            <div align="center" style="height:5%; width:100%; font-size:22px; color: #b2b2b2" id="userpwd_txt">逻辑ID注册
            </div>
            <TABLE cellSpacing="0" cellPadding="0" width="100%" border="0" height="70%">
              <TR>
                <TD colspan="2" align="center">
                  <div id="prograss"><span id="percent" style="font-size:12px;"></span></div>
                </TD>
              </TR>
              <TR>
                <TD colspan="2" align="center" height="10">
                  <script language="JavaScript" type="text/javascript">
                    document.write(txt);
                  </script>
                </TD>
              </TR>
              <TR height="8">
                <TD colspan="2" align="center">
                  <div height="84">
                    <img id="frontpic" width="84" height="84" style="display:none; float:left; margin-left:338px;" />
                    <div id="regResult"
                      style="font-family: '微软雅黑';font-size:21px; color:#b2b2b2; float:left; margin: 26px 0 0 25px">
                    </div>
                  </div>
                </TD>
              </TR>
              <TR>
                <TD colspan="2" align="center">
                  <img src="/images/sure.gif" style="cursor:pointer;" value="" onClick="JumpTo();" />
                </TD>
              </TR>
              <TR>
                <TD align="center" colSpan="2" width="100%" height="64">
                  <font size="2">
                </TD>
              </TR>
              <TR>
                <TD align="left" colSpan="2" height="120"></TD>
              </TR>
            </TABLE>
          </TD>
        </TR>
      </TABLE>
    </div>
  </form>
</body>

</html>