<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
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
  var IsMaintWan = '<%HW_WEB_IfMainWanLink();%>';

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
    window.location = "/cu.html";
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div align="center" id="regsuccshow" style="display:none">
      <TABLE cellSpacing="0" cellPadding="0" align="center" border="0">
        <TBODY>
          <TR>
          </TR>
          <TR>
            <TD>
              <TABLE cellSpacing="0" cellPadding="0" align="middle" border="0">
                <TBODY>
                  <TR>
                    <script type="text/javascript" language="javascript">
                      if ('LNCU' == CfgMode.toUpperCase()) {
                        document.write('<TD align="center" style="width:935px;height:417px;" background="/images/cu_register_cubg.jpg">');
                      }
                      else {
                        document.write('<TD align="center" style="width:935px;height:417px;" background="/images/register_cubg.gif">');
                      }
                    </script>

                    <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
                      <TR>
                        <TD align="right" style="padding-right:30px;">
                          <script language="javascript">
                            if (IsMaintWan == 1) {
                              var starIdx = window.location.href.indexOf('://');
                              var subAddr = window.location.href.substr(starIdx + 3);
                              var br0Ip = subAddr.substring(0, subAddr.indexOf('/'));
                            }
                            if (CfgMode.toUpperCase() == 'LNCU') {
                              if (IsMaintWan != 1) {
                                document.write('<A href="http://' + br0Ip + ':' + httpport + '/cu.html"><FONT size="3" id="backlogin" color="#000000" style="font-weight:bold;font-size: 16px;">返回登录页面</FONT></A>');
                              }
                              else {
                                document.write('<A href="http://' + br0Ip + '/cu.html"><FONT size="3" id="backlogin" color="#000000" style="font-weight:bold;font-size: 16px;">返回登录页面</FONT></A>');
                              }
                            }
                            else {
                              if (IsMaintWan != 1) {
                                document.write('<A href="http://' + br0Ip + ':' + httpport + '/cu.html"><FONT size="3" id="backlogin" color="#3C1400" style="font-weight:bold;font-size: 16px;">返回登录页面</FONT></A>');
                              }
                              else {
                                document.write('<A href="http://' + br0Ip + '/cu.html"><FONT size="3" id="backlogin" color="#3C1400" style="font-weight:bold;font-size: 16px;">返回登录页面</FONT></A>');
                              }
                            }
                          </script>
                        </TD>
                      </TR>
                    </TABLE>
                    <div
                      style="position:relative; top:10px;left:-200px;height:20px; width:120px;font-family: '黑体';font-size:22px;font-weight:bolder;"
                      id="userpwd_txt">逻辑ID注册</div>
                    <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80">
                      <TD colSpan="2" height="80"></TD>
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
                      <TR>
                        <TD align="middle" colSpan="2" height="4"></TD>
                      </TR>
                      <TR height="8">
                        <TD colspan="2" align="center">
                          <img id="frontpic" width="37" height="37" style="display:none" />
                          <span id="regResult"
                            style="font-family: '微软雅黑';position:relative; top:-10px;font-size:18px; color:#3C1400; font-weight:bold;"></span>
                        </TD>
                      </TR>
                      <TR>
                        <TD colspan="2" align="center">
                          <img src="/images/returnbtn.gif" style="" value="" onClick="JumpTo();" />
                        </TD>
            </TD>
          </TR>
          <TR>
          <TR>
            <TD align="center" colSpan="2" width="100%" height="30">
              <font size="2">
            </TD>
          </TR>
          <TR>
            <TD align="left" colSpan="2" height="120"></TD>
          </TR>
      </TABLE>
      <TD width="78" rowSpan="3"></TD>
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