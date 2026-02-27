<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <script language="JavaScript" type="text/javascript">
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
      document.write('<title>中国移动</title>');
    }
    else if ('SHXCNCATV' == CfgMode.toUpperCase()) {
      document.write('<title>陕西广电</title>');
    } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
      document.write('<title>四川广电</title>');
    } else if (CfgMode.toUpperCase() == 'HUNCNCATV') {
      document.write('<title>湖南广电</title>');
    }
    else if ('GZGD' == CfgMode.toUpperCase()) {
      document.write('<title>贵州广电网络</title>');
    }
    else {
      document.write('<title>中国电信—我的E家</title>');
    }
  </script>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">

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
  var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
  var MngtOnlineJS = '<%HW_WEB_GetFeatureSupport(HW_SSMP_PONONLINE_DISABLEREG);%>';
  var MngtScct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SCCT);%>';
  var MngtBjct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_BJCT);%>';
  var MngtTjct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_TJCT);%>';
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>'
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var MngtSdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SDCT);%>';
  var MngtHljct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HLJCT);%>';
  var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';
  var ontAccessType = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.AccessType);%>';
  var is10GPON = '<%HW_WEB_GetFeatureSupport(HW_AMP_FEATURE_10GPON);%>';
  var loadedcolor = 'orange';
  var unloadedcolor = 'white';
  var bordercolor = 'orange';
  var e8cBarHeight = 15;
  var e8cBarWidth = 300;
  var ns4 = (document.layers) ? true : false;
  var ie4 = (document.all) ? true : false;
  var PBouter;
  var PBdone;
  var PBbckgnd;
  var txt = '';

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

  if (ns4) {
    txt += '<table border=0 cellpadding=0 cellspacing=0><tr><td>';
    txt += '<ilayer name="PBouter" visibility="hide" height="' + e8cBarHeight + '" width="' + e8cBarWidth + '">';
    txt += '<layer width="' + e8cBarWidth + '" height="' + e8cBarHeight + '" bgcolor="' + bordercolor + '" top="0" left="0"></layer>';
    txt += '<layer width="' + (e8cBarWidth - 2) + '" height="' + (e8cBarHeight - 2) + '" bgcolor="' + unloadedcolor + '" top="1" left="1"></layer>';
    txt += '<layer name="PBdone" width="' + (e8cBarWidth - 2) + '" height="' + (e8cBarHeight - 2) + '" bgcolor="' + loadedcolor + '" top="1" left="1"></layer>';
    txt += '</ilayer></td></tr></table>';
  } else {
    txt += '<div id="PBouter" style="position:relative; visibility:hidden; background-color:' + bordercolor + '; height:' + e8cBarHeight + 'px; width:' + e8cBarWidth + 'px;">';
    txt += '<div style="position:absolute; left:1px; top:1px; width:' + (e8cBarWidth - 2) + 'px; height:' + (e8cBarHeight - 2) + 'px; background-color:' + unloadedcolor + '; font-size:1px;"></div>';
    txt += '<div id="PBdone" style="position:absolute; left:1px; width:0px; top:1px; height:' + (e8cBarHeight - 2) + 'px; background-color:' + loadedcolor + '; font-size:1px;"></div></div>';
  }

  function Submit(type) {
    if (CheckForm(type) == true) {
      var Form = new webSubmitForm();
      AddSubmitParam(Form, type);
      Form.submit();
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

  function LoadFrame() {
    if (((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV')) && (parseInt(SuccInfos.Status) == 97)) {
      document.getElementById('regsuccshow').style.display = "";
      document.getElementById("regResult").innerHTML = "设备已注册，无需再注册，需恢复出厂配置才可再注册。";
    }
    else if (((parseInt(SuccInfos.Status) == 0) || (MngtGdct == 1)) && (parseInt(SuccInfos.Result) == 1)) {
      document.getElementById('regsuccshow').style.display = "";
      if (MngtGdct == 1) {
        document.getElementById("regResult").innerHTML = "已注册成功，无需再注册。";
      }
      else if (1 == MngtOnlineJS) {
        document.getElementById("regResult").innerHTML = "宽带识别码（LOID）录入已成功。";
      }
      else {
        if (IsCTRGAreaInformBind2()) {
          document.getElementById("regResult").innerHTML = "宽带识别码（LOID）录入已成功。";
        }
        else {
          document.getElementById("regResult").innerHTML = "设备已注册，无需再注册，需恢复出厂配置才可再注册。";
        }
      }
    }
    else if ((MngtGdct == 1) && (parseInt(SuccInfos.Status) == 5)) {
      document.getElementById('regsuccshow').style.display = "";
      document.getElementById("regResult").innerHTML = "已注册成功，无需再注册。";
    }
    else if (MngtSdct == 1) {
      document.getElementById('regsuccshow').style.display = "";
      document.getElementById("regResult").innerHTML = "宽带识别码（LOID）录入已成功。";
    }
    else {
      if (1 == MngtOnlineJS) {
        if (window.location.href.indexOf("loid.cgi?") > 0) {
          window.location = "/loidgregsuccess.asp";
        }
        else {
          document.getElementById('regsuccshow').style.display = "";
          document.getElementById("regResult").innerHTML = "宽带识别码（LOID）录入已成功。";
        }
      }
      else {
        window.location = "/login.asp";
      }
    }
  }

  function JumpTo() {
    window.location = "/login.asp";
  }

  function SelfChecking() {
    var SubmitForm = new webSubmitForm();

    SubmitForm.addParameter('x.X_HW_Token', getAuthToken());
    SubmitForm.setAction('selfCheck.cgi?' + 'RequestFile=selfChecking.asp');
    SubmitForm.submit();

  }

  function RestoreDefaultCfgAll() {
    if ('CQCT' == CfgMode.toUpperCase()) {
      if (confirm("您确定想要恢复到出厂值？")) {
        var Form = new webSubmitForm();
        Form.addParameter('x.X_HW_Token', getAuthToken());
        Form.setAction('fjrestoredcfg.cgi?RequestFile=loidgrestoresuccess.html');
        Form.submit();
      }
    }
    else {
      window.location = "/loidgrestore.asp";
    }
  }

  function AddSubmitParam(SubmitForm, type) {
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div align="center" id="regsuccshow" style="display:none">
      <TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0" style="position: relative; ">
        <TBODY>
          <TR>
            <script language="JavaScript" type="text/javascript">
              if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                document.write('<TD ><IMG height="137" src="/images/register_banner_cmcc.jpg" width="808"></TD> ');
              }
              else if ('SHXCNCATV' == CfgMode.toUpperCase()) {
                document.write('<TD><div style="height: auto; overflow: hidden; width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block; float: left " height="70" src="/images/top_img_20K_shxcncatv.jpg" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip + ':' + httpport + '/login.asp" style=" right: 82px; top: 43px; display: block; font-family: 微软雅黑; position: absolute;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              } else if (CfgMode.toUpperCase() == 'SCCNCATV') {
                document.write('<TD><div style="height: auto; overflow: hidden; width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block; float: left " height="50" src="/images/top_sccncatv.jpg" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip + ':' + httpport + '/login.asp" style=" right: 82px; top: 30px; display: block; font-family: 微软雅黑; position: absolute;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              } else if (CfgMode.toUpperCase() == 'HUNCNCATV') {
                document.write('<TD><div style="height: auto; overflow: hidden; width: 80%; margin: auto; border-bottom: 4px solid #e3e3e3;"><IMG style="display: block; float: left " height="70" ></div></TD> ');
                document.write('<tr><TD><A href="http://' + br0Ip +':'+ httpport +'/login.asp" style=" right: 82px; top: 43px; display: block; font-family: 微软雅黑; position: absolute;"><font style="font-size: 15px;" color="#000000">返回登录页面</FONT></A></TD ></tr>');
              }
              else {
                document.write('<TD ><IMG height="137" src="/images/register_banner.jpg" width="808"></TD> ');
              }
            </script>
          </TR>
          <TR>
            <TD>
              <TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0">
                <TBODY>
                  <TR>
                    <script type="text/javascript">
                      if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                        document.write('<TD width="77" rowSpan="3"></TD> ');
                      }
                      else {
                        document.write('<TD width="77" background="/images/bg.gif" rowSpan="3"></TD>');
                      }
                    </script>
                    <script language="javascript">
                      if (1 == MngtScct) {
                        document.write('<TD align="center" width="653" height="323" background="/images/register_gdinfo_scct.jpg">');
                      }
                      else if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                        document.write('<TD align="center" width="653" height="323" >');
                      }
                      else {
                        document.write('<TD align="center" width="653" height="323" background="/images/register_gdinfo.jpg">');
                      }
                    </script>
                    <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
                      <TR>
                        <TD align="right">
                          <script language="javascript">
                            if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {

                            }
                            else {
                              document.write('<A href="http://' + br0Ip + ':' + httpport + '/login.asp"><font style="font-size: 14px;" color="#000000">返回登录页面</FONT></A>');
                            }
                          </script>
                        </TD>
                      </TR>
                    </TABLE>
                    <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">
                      <script language="javascript">
                        if (1 != IsLAN) {
                          if ((MngtOnlineJS == 1) || (MngtGdct == 1) || (1 == MngtSdct)) {
                            document.write('<TD colSpan="2" height="32"></TD><TR></TR>');
                          }
                          else if (MngtScct == 1) {
                            ;
                          }
                          else if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                            ;
                          }
                          else {
                            document.write('<TD colSpan="2" height="32"></TD><TR><TD align="middle" colSpan="2" width="400" height="25" style="font-size: 13px;">提示：在注册过程中不要随意拔插光纤（10分钟内）</TD></TR>')
                          }
                        }
                      </script>

                      <script language="javascript">
                        if (1 != IsLAN) {
                          if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                            if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                              document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '终端</TD></TR>');

                            }
                            else {
                              document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '终端</TD></TR>');

                            }

                          }
                          else if (1 == MngtScct) {
                            document.write('<TR>');
                            if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                              if (1 == IsRhGateway) {
                                if (1 == E8CRONGHEFlag) {
                                  document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">GPON宽带融合终端注册</TD>');
                                }
                                else {
                                  document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">GPON上行融合智能终端注册</TD>');
                                }
                              }
                              else if (1 == IsCTRG) {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">GPON上行天翼网关</TD>');
                              }
                              else if ('SHXCNCATV' == CfgMode.toUpperCase()) {
                                ;
                              }
                              else if ('GZGD' == CfgMode.toUpperCase()) {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">GPON终端注册</TD>');
                              }
                              else {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">GPON的E8-C终端注册</TD>');
                              }
                            }
                            else {
                              var ponMode = (is10GPON === '1'? '10G EPON' : 'EPON');
                              if (1 == IsRhGateway) {
                                if (1 == E8CRONGHEFlag) {
                                  document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">' + ponMode + '宽带融合终端注册</TD>');
                                }
                                else {
                                  document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">' + ponMode + '上行融合智能终端注册</TD>');
                                }
                              }
                              else if (1 == IsCTRG) {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">' + ponMode + '上行天翼网关</TD>');
                              }
                              else if ('SHXCNCATV' == CfgMode.toUpperCase()) {
                                ;
                              }
                              else if ('GZGD' == CfgMode.toUpperCase()) {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">' + ponMode + '终端注册</TD>');
                              }
                              else {
                                document.write('<TD align="left" colSpan="2" height="10" style="font-size: 13px;">' + ponMode + '的E8-C终端注册</TD>');
                              }
                            }
                            document.write('</TR>');
                            document.write('<TD colSpan="2" height="32"></TD>');
                          }
                          else if (MngtGdct == 1) {

                            if (1 == IsRhGateway) {
                              if (1 == E8CRONGHEFlag) {
                                if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">GPON宽带融合终端</strong></TD><TR>');
                                }
                                else {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">EPON宽带融合终端</strong></TD><TR>');
                                }
                              }
                              else {
                                if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">GPON上行融合智能终端</strong></TD><TR>');
                                }
                                else {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">EPON上行融合智能终端</strong></TD><TR>');
                                }
                              }
                            }
                            else if (1 == IsCTRG) {
                              if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">GPON上行天翼网关</strong></TD><TR>');
                              }
                              else {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">EPON上行天翼网关</strong></TD><TR>');
                              }
                            }
                            else {
                              if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">GPON上行E8-C终端</strong></TD><TR>');
                              }
                              else {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 18px;"><strong style="color:#FF0033">EPON上行E8-C终端</strong></TD><TR>');
                              }
                            }

                            document.write('<TD colSpan="2" height="16"></TD>');

                          }
                          else if ((MngtOnlineJS == 1) || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                            ;
                          }
                          else {
                            if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
                              if (1 == IsRhGateway) {
                                if (1 == E8CRONGHEFlag) {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '宽带融合终端</TD></TR>');
                                }
                                else {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '上行融合智能终端</TD></TR>');
                                }
                              }
                              else if (1 == IsCTRG) {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '上行天翼网关</TD></TR>');
                              }
                              else if ('GZGD' == CfgMode.toUpperCase()) {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '终端</TD></TR>');
                              }
                              else {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '的E8-C终端</TD></TR>');
                              }
                            }
                            else {
                              if (1 == IsRhGateway) {
                                if (1 == E8CRONGHEFlag) {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '宽带融合终端</TD></TR>');
                                }
                                else {
                                  document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '上行融合智能终端</TD></TR>');
                                }
                              }
                              else if (1 == IsCTRG) {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '上行天翼网关</TD></TR>');
                              }
                              else if ('GZGD' == CfgMode.toUpperCase()) {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '终端</TD></TR>');
                              }
                              else {
                                document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是' + ontAccessType.toUpperCase() + '的E8-C终端</TD></TR>');
                              }
                            }
                          }
                        }
                      </script>
                      <TR>
                        <TD colspan="2" align="center">
                          <div id="prograss"><span id="percent" style="font-size:12px;"></span></div>
                        </TD>
                      </TR>
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
                        <TD colspan="2" align="center"><span id="regResult" style="font-size:16px;"></span></TD>
                      </TR>
                      <TR>
                        <TD colspan="2" valign="top" align="right" width="130" height="25" align="center"></TD>
                      </TR>
                      <TR>
                        <TD colspan="2" align="center">
                          <script language="JavaScript" type="text/javascript">
                            if ((MngtGdct == 1) || (1 == MngtOnlineJS) || (MngtSdct == 1)) {
                              document.write('<input type="button" class="submit" style="font-size: 13px;" value="返 回" onclick="JumpTo();"/>');

                            }
                            else {

                              if ((CfgMode.toUpperCase() == 'SCCT') || (CfgMode.toUpperCase() == 'SCSCHOOL')) {
                                document.write('<input type="button" style="margin-left:10px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                                if (1 != IsLAN) {
                                  document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="selfCheck" id="resetValue" class="submit" value="自 检" onclick="SelfChecking();"/>');
                                }
                                document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="resetValue" id="resetValue" class="submit" value="恢复出厂配置" onclick="RestoreDefaultCfgAll();"/>');
                              }
                              else if (MngtBjct == 1) {
                                document.write('<input type="button" style="margin-left:10px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                                document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="selfCheck" id="resetValue" class="submit" value="自 检" onclick="SelfChecking();"/>');
                                document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="resetValue" id="resetValue" class="submit" value="恢复出厂配置" onclick="RestoreDefaultCfgAll();"/>');
                              }
                              else if (MngtTjct == 1) {
                                document.write('<input type="button" style="margin-left:10px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                                document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="selfCheck" id="resetValue" class="submit" value="自 检" onclick="SelfChecking();"/>');
                                document.write('<input type="button" style="margin-left:40px;font-size: 13px;" name="resetValue" id="resetValue" class="submit" value="恢复出厂配置" onclick="RestoreDefaultCfgAll();"/>');
                              }
                              else if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                                document.write('<input type="button" style="margin-left:70px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                              }
                              else {
                                document.write('<input type="button" style="margin-left:150px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                                document.write('<input type="button" style="margin-left:60px;font-size: 13px;" name="resetValue" id="resetValue" class="submit" value="恢复出厂配置" onclick="RestoreDefaultCfgAll();"/>');
                              }

                            }
                          </script>
                        </TD>
                      </TR>
                      <TR>
                      <TR>
                        <script language="JavaScript" type="text/javascript">
                          if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                            document.write('<TD align="center" colSpan="2" width="100%" height="30"><font style="font-size: 14px;">中国移动客动服热线10086号</font></TD>');
                          }
                          else if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                            ;
                          }
                          else if ('GZGD' == CfgMode.toUpperCase()) {
                            document.write('<TD align="center" colSpan="2" width="100%" height="30"><font style="font-size: 14px;">贵州广电客服热线96789号</font></TD>');
                          }
                          else {
                            document.write('<TD align="center" colSpan="2" width="100%" height="30"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD>');
                          }
                        </script>
                      </TR>
                      <TR>
                        <TD align="left" colSpan="2" height="60"></TD>
                      </TR>
                    </TABLE>
                    <script type="text/javascript">
                      if ((CfgMode.toUpperCase() == 'SHXCNCATV') || (CfgMode.toUpperCase() == 'SCCNCATV') || (CfgMode.toUpperCase() == 'HUNCNCATV')) {
                        document.write('<TD width="78" rowSpan="3"></TD> ');
                      }
                      else {
                        document.write('<TD width="78" background="/images/bg.gif" rowSpan="3"></TD>');
                      }
                    </script>
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