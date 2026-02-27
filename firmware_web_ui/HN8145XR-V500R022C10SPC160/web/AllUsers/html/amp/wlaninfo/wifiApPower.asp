<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  id="Page" xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <meta http-equiv="Content-Type" content="text/html"; charset="utf-8">
    <meta http-equiv="Pragma" content="no-cache" />
    <link rel="stylesheet"  href='../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>' type='text/css'>
    <link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
    <script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(ampdes.html);%>"></script>
    <script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
    <script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
    <script src="../../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
    <script>
      var optimizeEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_WIFIInfo.WifiTpcOptimize.DwmEnable);%>';
      var optimizeState = '1';

      function setOptimizeState() {
        $.ajax({
          type : "POST",
          async : false,
          cache : false,
          url : "getOptimizeState.asp",
          success : function(data) {
            optimizeState = data;
          }
        });
      }

      function SubmitEnable() {
        setOptimizeState();
        if (optimizeState === '1') {
          alert(cfg_wlan_ap_power_language['ap_power_set_desc']);
          loadframe();
          return;
        }

        var enable = getCheckVal('optimizeEnable');
        var Form = new webSubmitForm();
        Form.addParameter('x.DwmEnable', enable);
        Form.setAction('set.cgi?x=InternetGatewayDevice.X_HW_WIFIInfo.WifiTpcOptimize&RequestFile=html/amp/wlaninfo/wifiApPower.asp');
        Form.addParameter('x.X_HW_Token', getValue('onttoken'));
        Form.submit();
      }

      function loadframe() {
        setCheck("optimizeEnable", optimizeEnable);
        var scnVar = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.LANDevice.1.X_HW_SCN.Enable);%>';
        if (scnVar === '1') {
          setDisable('optimizeEnable', 1);
        }

        var frame = '<%HW_WEB_GetSPEC(SSMP_SPEC_WEB_FRAME.STRING);%>';
        if ((frame == "frame_CMCC") || (frame == "frame_CTCOM")) {
          setDisplay('head_title', 1);
        }
      }
    </script>
    <style>
      .mainbody {
        margin-left: 30px; 
        margin-right: 30px;
      }
    </style>
  </head>
  <body  class="mainbody" onload="loadframe();">
    <input type="hidden" id="onttoken"  name="onttoken" value="<%HW_WEB_GetToken();%>"/>
    <div class="PageTitle_title" id="head_title" style="display: none;"><script>document.write(cfg_wlan_ap_power_language['ap_power_title'])</script></div>
    <script language="JavaScript" type="text/javascript">
        var apPowerSummary = "1. " +  GetDescFormArrayById(cfg_wlan_ap_power_language, "ap_power_desc") + "<br>" +
                             "2. " + GetDescFormArrayById(cfg_wlan_ap_power_language, "ap_power_srcn_desc");
        HWCreatePageHeadInfo("wanBackConftitle", GetDescFormArrayById(cfg_wlan_ap_power_language, "ap_power_title"), apPowerSummary, false);
    </script> 
    <div class="title_spread"></div>
    <div id="dacEnableDiv">
      <input type="checkbox" id="optimizeEnable" name="optimizeEnable" onClick="SubmitEnable();">
      <span class="gray">
        <script>
          document.write(cfg_wlan_ap_power_language["ap_power_enabl"]);
        </script>
      </span>
    </div>
  </body>
</html>