<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <title>中国移动</title>
</head>
<style>
  .input_time {
    border: 0px;
  }

  * {
    margin: 0;
    padding: 0;
  }
</style>
<script language="javascript">
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>';
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
  var loadedcolor = 'orange';       // PROGRESS BAR COLOR
  var unloadedcolor = 'white';     // COLOR OF UNLOADED AREA
  var bordercolor = 'orange';        // COLOR OF THE BORDER
  var barheight = 15;              // HEIGHT OF PROGRESS BAR IN PIXELS
  var barwidth = 300;              // WIDTH OF THE BAR IN PIXELS
  var ns4 = (document.layers) ? true : false;
  var ie4 = (document.all) ? true : false;
  var PBouter;
  var PBdone;
  var PBbckgnd;
  var txt = '';
  var ZJCmccRms = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_ZJCMCC_RMS);%>';
  var CfgFtWord = '<%HW_WEB_GetCfgMode();%>';
  var PwdInfo = '<%HW_WEB_GetCMCCAuthPwd();%>';

  function stResultInfo(domain, Result, Status, UserName, X_HW_RmsRegType, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
    this.UserName = UserName;
    this.X_HW_RmsRegType = X_HW_RmsRegType;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status|UserName|X_HW_RmsRegType, stResultInfo);%>;
  var SuccInfos = stResultInfos[0];

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
      if ((CfgFtWord.toUpperCase() == 'AHCMCC_RMS') || (CfgFtWord.toUpperCase() == 'AHCMCC_RMS2')) {
        if (parseInt(SuccInfos.X_HW_RmsRegType) == 0) {
          document.getElementById('regsuccshow').style.display = "";
          document.getElementById("regResult").innerHTML = "该设备已注册成功（LOID：" + SuccInfos.UserName + "），如需重新注册请恢复出厂设置";
        }
        else {
          document.getElementById('regsuccshow').style.display = "";
          document.getElementById("regResult").innerHTML = "该设备已注册成功（PASSWORD：" + PwdInfo + "），如需重新注册请恢复出厂设置";
        }
      }
      else {
        document.getElementById('regsuccshow').style.display = "";
        document.getElementById("regResult").innerHTML = "已经注册成功，无需再注册。";
      }
    }
    else {
      /* 否则跳转到首页 */
      window.location = "/login.asp";
    }

  }

  function JumpTo() {
    window.location = "/login.asp";
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div align="center" id="regsuccshow" style="display:none">
      <TABLE style="width:100%;height:80px;background-color:#efefef;">
        <TR>
          <TD style="position:relative;">
            <img src="/images/cmccdevice_logo.gif" alt="" style="position:absolute;top:15px;left:323px;">
            <script language="javascript">
              document.write('<a href="http://' + br0Ip + ':' + httpport + '/login.asp" style="position:absolute;top:36px;left:1221px;width:120px;color:#0081cc;font-size:15px;font-weight:bold;text-decoration:none;">返回登录页面></a>');
            </script>
          </TD>
        </TR>

        <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80">
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
          <tr>
            <TD colspan="2" align="center">
              <div id="prograss"><span id="percent" style="font-size:12px;"></span></div>
            </TD>
          </tr>
          <TR>
            <TD colspan="2" align="center">
              <script language="JavaScript" type="text/javascript">
                document.write(txt);
              </script>
            </TD>
          </TR>
          <TR>
            <TD align="middle" colSpan="2" height="4"></TD>
          </TR>
          <TR height="8">
            <TD colspan="2" align="center" style="padding-top:15px;">
              <span id="regResult" style="font-size:15px;font-weight:bold;"></span>
            </TD>
          </TR>
          <TR>
            <TD colspan="2" align="center" style="padding-top:40px;">
              <input type="button" class="submit" value="返 回" onclick="JumpTo();"
                style="width:80px;height:35px;background:url(/images/button_cancel.gif);border-radius:6px;border-width:0;font-size:15px;font-weight:bold;color:#5c5d55;" />
            </TD>
          </TR>
          <TR>
            <script language="javascript">
              if (ZJCmccRms != 1) {
                document.write('<TD align="center" style="padding-top:20px;font-size:15px;font-weight:bold;color:#5c5d55;text-align:center;">中国移动客服热线10086号</TD>');
              }
            </script>

          </TR>
          <TR>
            <TD align="left" colSpan="2" height="60"></TD>
          </TR>
        </TABLE>
      </TABLE>
    </div>
  </form>
</body>

</html>