<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    var BinWord = '<%HW_WEB_GetBinMode();%>';
    if (BinWord.toUpperCase() == 'A8C') {
      document.write('<title>中国电信-政企网关</title>');
    }
    else {
      document.write('<title>中国电信—我的E家</title>');
    }
  </script>



</head>
<style>
  .input_time {
    border: 0px;
  }
</style>
<script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
<script language="javascript">
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
  var IsCTRG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>'
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';
  var loidRegRet = '<%webGetLoidRegRet();%>';
  var E8CRONGHEFlag = '<%HW_WEB_GetFeatureSupport(FT_SHMP_RONGHE);%>';
  var startInterval;
  var stopInterval;

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
  var interval;

  txt += getLayerStr(ns4, barheight, barwidth, bordercolor, barheight, unloadedcolor, loadedcolor);

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

  function Submit(type) {
    if (CheckForm(type) == true) {
      var Form = new webSubmitForm();
      AddSubmitParam(Form, type);
      Form.submit();
    }
  }

  function getRegCurBussTips(CurBuss) {
    var strServiceName = "";
    if (CurBuss == "IPTV" || CurBuss == "ITV") {
      strServiceName += "iTV";
    }
    else if (CurBuss == "INTERNET") {
      strServiceName += "上网";
    }
    else if (CurBuss == "VOICE" || CurBuss == "VOIP") {
      strServiceName += "语音";
    }
    else if (CurBuss == "OTHER") {
      strServiceName += "其它";
    }

    var LanDesInfoStr = "ITMS平台正在下发" + strServiceName + "业务数据，请勿断电或拔网线。";
    var PonDesInfoStr = "ITMS平台正在下发" + strServiceName + "业务数据，请勿断电或拔光纤。";
    var Step2ShowInfo = (1 == IsLAN) ? LanDesInfoStr : PonDesInfoStr;

    return Step2ShowInfo;
  }


  function getRegSuccessTips(AllBuss) {
    if (AllBuss == "") {
      if (1 == IsCTRG) {
        return "ITMS平台业务数据下发成功，欢迎使用天翼网关。";
      }
      else {
        return "ITMS平台业务数据下发成功，欢迎使用业务。";
      }
    }

    var strProvisioning = AllBuss.split('+');
    var strNewProvisioning = '';
    var strNum;

    for (i = 0; i < strProvisioning.length; i++) {
      if (strProvisioning[i].toUpperCase() == "IPTV" || strProvisioning[i].toUpperCase() == "ITV") {
        strProvisioning[i] = "iTV";
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
    if (1 == IsCTRG) {
      return "ITMS平台业务数据下发成功，共下发了" + strNewProvisioning + strNum + "个业务，欢迎使用天翼网关。";
    }
    else {
      return "ITMS平台业务数据下发成功，共下发了" + strNewProvisioning + strNum + "个业务，欢迎使用业务。";
    }
  }

  function analysisResult(ResResult) {
    var RegPercent = ResResult.split(";")[0];
    var RegStatusStr = ResResult.split(";")[1];
    var RegStatus = RegStatusStr.split(",")[1];

    var BussStr = "";
    if (ResResult.split(";").length > 2) {
      BussStr = ResResult.split(";")[2];
    }

    if (RegPercent == 0) {
      setPrograss(0, 0);
      document.getElementById('percent').innerHTML = "";
      startInterval = 0;
      stopInterval = 1;
    }
    else {
      if (RegPercent == 100) {
        var AllBuss = "";
        if (BussStr.split(",").length > 1) {
          AllBuss = BussStr.split(',')[1];
        }

        document.getElementById("ftitle").innerHTML = getRegSuccessTips(AllBuss);
        setPrograss(1, 298);
        document.getElementById('percent').innerHTML = RegPercent + "%";

        startInterval = 0;
        stopInterval = 1;
        return;
      }
      setPrograss(1, (RegPercent * 298) / 100);
      document.getElementById('percent').innerHTML = RegPercent + "%";
      if (RegStatus == "REGISTER_OLT") {
        if (RegPercent == 20) {
          document.getElementById("ftitle").innerHTML = "正在注册OLT。";
        }
        else if (RegPercent == 30) {
          if (1 == IsLAN) {
            document.getElementById("ftitle").innerHTML = "正在获取管理IP。";
          }
          else {
            document.getElementById("ftitle").innerHTML = "注册OLT成功，正在获取管理IP。";
          }
        }
        else if (RegPercent == 40) {
          document.getElementById("ftitle").innerHTML = "已获得管理IP，正在连接ITMS。";
        }
        return;
      }

      if (RegStatus == "REGISTER_OK_DOWN_BUSINESS") {
        if (RegPercent == 50) {
          document.getElementById("ftitle").innerHTML = "注册ITMS成功，等待ITMS平台下发业务数据。";
        }
        else if (RegPercent >= 60 && RegPercent < 100) {
          var CurBuss = "";
          if (BussStr.split(",").length > 1) {
            CurBuss = BussStr.split(",")[1];
          }
          document.getElementById("ftitle").innerHTML = getRegCurBussTips(CurBuss);
        }
        return;
      }
    }

    if (RegStatus == "REGISTER_OK") {
      var AllBuss = "";
      if (BussStr.split(",").length > 1) {
        AllBuss = BussStr.split(',')[1];
      }

      document.getElementById("ftitle").innerHTML = getRegSuccessTips(AllBuss);
      startInterval = 0;
      stopInterval = 1;
      return;
    }
    else if (RegStatus == "REGISTER_DEFAULT") {
      document.getElementById("ftitle").innerHTML = "初始设备未注册状态。";
    }
    else if (RegStatus == "REGISTER_REGISTED") {
      document.getElementById("ftitle").innerHTML = "设备已注册，无需再注册。";
    }
    else if (RegStatus == "REGISTER_TIMEOUT") {
      document.getElementById("ftitle").innerHTML = "在ITMS上注册超时！请检查线路后重试或联系客户经理或拨打10000。";
    }
    else if (RegStatus == "REGISTER_NOMATCH_NOLIMITED" || RegStatus == "REGISTER_NOACCOUNT_NOLIMITED" || RegStatus == "REGISTER_NOUSER_NOLIMITED") {
      document.getElementById("ftitle").innerHTML = "在ITMS上注册失败！请检查宽带识别码（LOID）和密码是否正确或联系客户经理或拨打10000。";
    }
    else if (RegStatus == "REGISTER_NOMATCH_LIMITED" || RegStatus == "REGISTER_NOACCOUNT_LIMITED" || RegStatus == "REGISTER_NOUSER_LIMITED") {
      document.getElementById("ftitle").innerHTML = "在ITMS上注册失败！请3分钟后重试或联系客户经理或拨打10000。";
    }
    else if (RegStatus == "REGISTER_OLT_FAIL") {
      if (1 == IsCTRG) {
        document.getElementById("ftitle").innerHTML = "在OLT上注册失败，请检查光信号灯（红色）是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理或拨打10000。";
      }
      else {
        document.getElementById("ftitle").innerHTML = "在OLT上注册失败，请检查光信号灯是否处于熄灭状态、宽带识别码（LOID）和密码是否正确或联系客户经理或拨打10000。";
      }
    }
    else if (RegStatus == "REGISTER_POK") {
      document.getElementById("ftitle").innerHTML = "ITMS下发业务异常！请联系客户经理或拨打10000。";
    }
    else {
      document.getElementById("ftitle").innerHTML = "其它原因的注册失败。";
    }

    startInterval = 0;
    stopInterval = 1;
    return;
  }

  function myrefresh() {
    var RegResult;
    $.ajax({
      type: "POST",
      async: false,
      cache: false,
      timeout: 4000,
      url: "asp/getregret.asp",
      success: function (data) {
        RegResult = data;
      }
    });

    analysisResult(RegResult);

    if (stopInterval == 1) {
      clearInterval(interval);
    }
  }

  function setRefreshInterval(time) {

    interval = setInterval('myrefresh()', time);

    return;
  }

  function LoadFrame() {
    startInterval = 1;
    stopInterval = 0;
    analysisResult(loidRegRet);
    if (startInterval == 1) {
      setRefreshInterval(2000);
    }

    return;
  }

  function JumpTo() {
    clearTimeout(interval);
    window.location = "/login.asp";
  }

  function AddSubmitParam(SubmitForm, type) {
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div align="center" id="regsuccshow">
      <TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0" style="position: relative;"
        id="RegFail">
        <TBODY>
          <TR>
            <script language="JavaScript" type="text/javascript">
              document.write('<TD ><IMG height="137" src="/images/register_banner.jpg" width="808"></TD> ');
            </script>
          </TR>
          <TR>
            <TD>
              <TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0">
                <TBODY>
                  <TR>
                    <script type="text/javascript">
                      document.write('<TD width="77" background="/images/bg.gif" rowSpan="3"></TD>');
                      document.write('<TD align="center" width="653" height="323" background="/images/register_gdinfo.jpg">');
                    </script>
                    <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
                      <TR>
                        <TD align="right">
                          <script language="javascript">
                            document.write('<A href="http://' + br0Ip + ':' + httpport + '/login.asp"><font style="font-size: 14px;" color="#000000">返回登录页面</FONT></A>');
                          </script>
                        </TD>
                      </TR>
                    </TABLE>
                    <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">
                      <script language="javascript">
                        if (1 != IsLAN) {
                          document.write('<TD colSpan="2" height="32"></TD><TR><TD align="middle" colSpan="2" width="400" height="25" style="font-size: 13px;">提示：在注册过程中不要随意拔插光纤（10分钟内）</TD></TR>')
                          if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
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
                              document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是GPON的E8-C终端</TD></TR>');
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
                              document.write('<TR><TD align="middle" colSpan="2" height="25" style="font-size: 13px;">该终端是EPON的E8-C终端</TD></TR>');
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
                        <TD colspan="2" align="center">
                          <div>
                            <font id="ftitle" style="font-size:14px;"></font>
                          </div>
                        </TD>
                      </TR>
                      <TR>
                        <TD colspan="2" valign="top" align="right" width="130" height="10" align="center"></TD>
                      </TR>
                      <TR>
                        <TD colspan="2" align="center">
                          <script language="JavaScript" type="text/javascript">
                            document.write('<input type="button" style="margin-left:10px;font-size: 13px;" class="submit" value="返 回" onclick="JumpTo();"/>');
                          </script>
                        </TD>
                      </TR>
                      <TR>
                      <TR>
                        <script language="JavaScript" type="text/javascript">
                          document.write('<TD align="center" colSpan="2" width="100%" height="30"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD>');
                        </script>
                      </TR>
                      <TR>
                        <TD align="left" colSpan="2" height="60"></TD>
                      </TR>
                    </TABLE>
                    <script type="text/javascript">
                      document.write('<TD width="78" background="/images/bg.gif" rowSpan="3"></TD>');
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