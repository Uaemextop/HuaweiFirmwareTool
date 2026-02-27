<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <META HTTP-EQUIV="Pragma" CONTENT="no-cache">
  <link rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <title>LOID</title>
  <script language="JavaScript" type="text/javascript">
    var JSLoid = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_UserInfo.JSCT_UserName);%>';

    var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
    var MngtCtrgMode = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CTRG);%>';
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    var CfgFtWordArea = '<%GetConfigAreaInfo();%>';
    var UrlLoidValue = "";
    var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';

    function hexDecode(str) {
      if (typeof str === 'string' && /\\x(\w{2})/.test(str)) {
        return str.replace(/\\x(\w{2})/g, function (_, $1) { return String.fromCharCode(parseInt($1, 16)) });
      }
      return str;
    }

    function LoadFrame() {
      if (1 == MngtGdct) {
        document.getElementById('url_loid').style.display = 'none';
        SetJSLoid();
      }

      else if ('SZCT' == CfgMode.toUpperCase() || 'XJCT' == CfgMode.toUpperCase()) {
      }
      else {
        document.getElementById('url_loid').style.display = 'none';
        SetJSLoid();
      }
    }

    function TextLoidTrans(sValue) {
      sValue = sValue.toString().replace(/&nbsp;/g, " ");
      sValue = sValue.toString().replace(/&quot;/g, "\"");
      sValue = sValue.toString().replace(/&gt;/g, ">");
      sValue = sValue.toString().replace(/&lt;/g, "<");
      sValue = sValue.toString().replace(/&#39;/g, "\'");
      sValue = sValue.toString().replace(/&#40;/g, "\(");
      sValue = sValue.toString().replace(/&#41;/g, "\)");
      sValue = sValue.toString().replace(/&amp;/g, "&");
      return sValue;
    }


    var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
    if (null != stResultInfos && null != stResultInfos[0]) {
      var Infos = stResultInfos[0];
    }
    else {
      var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
      var Infos = stResultInfos[0];
    }

    function stResultInfo(domain, Result, Status) {
      this.domain = domain;
      this.Result = Result;
      this.Status = Status;
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

    var opticInfo = -20;
    var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';


    function IsOpticPowerEorrorForGDCheck() {
      if (ontPonMode.toUpperCase() == 'GPON') {
        if (parseInt(opticInfo) > -31 && parseInt(opticInfo) < -8) {
          return false;
        }

        return true;
      }
      else if (ontPonMode.toUpperCase() == 'EPON') /* EPON */ {
        if (parseInt(opticInfo) > -31 && parseInt(opticInfo) < -3) {
          return false;
        }

        return true;
      }

      return true;
    }

    function IsOpticalNomal() {
      if (1 == IsLAN) {
        return true;
      }
      else {
        return opticInfo != "--";
      }

    }

    function LoidRegSubmit(jsloid, SubmitUrl) {
      var PrevTime = new Date();
      setCookie("lStartTime", PrevTime);
      setCookie("StepStatus", "0");
      setCookie("CheckOnline", "0");
      setCookie("lastPercent", "0");
      setCookie("GdTR069WanStatus", "0");
      setCookie("GdDispStatus", "0");
      setCookie("GdTR096WanIp", "0");
      setCookie("RegisterStep", "RPON");
      setCookie("SRStepInfo", "0;99;99");

      var paralist = "";
      paralist += "x.JSCT_UserName=" + jsloid;
      paralist += "&x.UserName=" + jsloid;

      $.ajax({
        type: "POST",
        async: false,
        cache: false,
        data: getDataWithToken(paralist),
        url: "loid.cgi?x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=" + SubmitUrl,
        success: function (data) {
        }
      });

      window.location = "/" + SubmitUrl;
    }

    function SetJSLoid() {
      var jsloid = TextLoidTrans(JSLoid);

      if ((1 == MngtCtrgMode) && (('E8C' == CfgMode.toUpperCase() && CfgFtWordArea.toUpperCase() == 'CHOOSE'))) {
        window.location = '/loidchooseareaTyUrl.asp';
        return;
      }
      else if (('E8C' == CfgMode.toUpperCase() && CfgFtWordArea.toUpperCase() == 'CHOOSE')) {
        window.location = '/loidchooseareaUrl.asp';
        return;
      }

      if (1 == MngtGdct) {
        $.ajax({
          type: "POST",
          async: false,
          cache: false,
          url: "asp/GetUrlLoid.asp",
          success: function (data) {
            UrlLoidValue = data;
          }
        });

        jsloid = TextLoidTrans(UrlLoidValue);
      }

      if (jsloid == "" || jsloid == "6877687712345678") {
        alert("需要烧制的终端序列号不能为空。");
        return false;
      }

      if (24 < jsloid.length) {
        alert("需要烧制的终端序列号长度必须在1到24之间");
        return false;
      }

      if (!(((jsloid.charAt(0) >= '0') && (jsloid.charAt(0) <= '9'))
        || ((jsloid.charAt(0) >= 'A') && (jsloid.charAt(0) <= 'Z'))
        || ((jsloid.charAt(0) >= 'a') && (jsloid.charAt(0) <= 'z')))) {
        alert("终端序列号第一个字符必须是数字（0-9）或字母（a-z,A-Z）。");
        return false;
      }

      if (!(((jsloid.charAt(jsloid.length - 1) >= '0') && (jsloid.charAt(jsloid.length - 1) <= '9'))
        || ((jsloid.charAt(jsloid.length - 1) >= 'A') && (jsloid.charAt(jsloid.length - 1) <= 'Z'))
        || ((jsloid.charAt(jsloid.length - 1) >= 'a') && (jsloid.charAt(jsloid.length - 1) <= 'z')))) {
        alert("终端序列号最后一个字符必须是数字（0-9）或字母（a-z,A-Z）。");
        return false;
      }

      if (1 == MngtGdct) {
        if (parseInt(Infos.Result) == 1) {
          if (0 == parseInt(Infos.Status)) {
            if (!IsCTRGAreaInformBind2()) {
              window.location = "/loidgregsuccess.asp";
              return;
            }
          }
        }

        if ((parseInt(Infos.Status) == 5) && (MngtGdct == 1)) {
          window.location = "/loidgregsuccess.asp";
          return;
        }
        if (1 != IsLAN) {
          $.ajax({
            type: "POST",
            async: false,
            cache: false,
            timeout: 4000,
            url: "/asp/GetOpticRxPower.asp",
            success: function (data) {
              opticInfo = hexDecode(data);
              GetGDCTOpticAbnormal = IsOpticPowerEorrorForGDCheck();
            }
          });


          if (('1' == GetGDCTOpticAbnormal) || (!IsOpticalNomal())) {
            var PrevTime = new Date();
            setCookie("lStartTime", PrevTime);
            setCookie("StepStatus", "0");
            setCookie("CheckOnline", "0");
            setCookie("lastPercent", "0");
            setCookie("GdTR069WanStatus", "0");
            setCookie("GdDispStatus", "0");
            setCookie("GdTR096WanIp", "0");
            setCookie("RegisterStep", "RPON");
            setCookie("SRStepInfo", "0;99;99");
            window.location = "/loidresult.asp";
            return;
          } else {
            LoidRegSubmit(jsloid, "loidresult.asp");
          }
        } else {
          LoidRegSubmit(jsloid, "loidresult.asp");
        }
      } else if ('SZCT' == CfgMode.toUpperCase() || 'XJCT' == CfgMode.toUpperCase()) {
        LoidRegSubmit(jsloid, "loidret.asp");
      } else {
        LoidRegSubmit(jsloid, "loidresult.asp");
      }
    }


    function CancelConfigLoid() {
    }
  </script>
</head>

<body id="url_loid" class="mainbody" onLoad="LoadFrame();">
  <table width="100%" height="10%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td class="prompt">
        <table width="100%" border="0" cellspacing="0" cellpadding="0">
          <tr>
            <td width="100%" align="center">
              <script language="JavaScript" type="text/javascript">
                document.write("需要烧制的终端序列号:" + JSLoid);
              </script>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
  <form>
    <table width="100%" border="0" cellpadding="0" cellspacing="0" class="tabal_bg">
      <tr>
        <td width="25%" height="35">&nbsp;</td>
        <td width="50%" height="35" align="center">
          <input name="cancelValue" id="cancelValue" type="button" class="submit" value=" 取消 "
            onClick="CancelConfigLoid();">&nbsp;&nbsp;
          <input name="btnApply" type="button" class="submit" value=" 确定 " onClick="SetJSLoid();">
        </td>
        <td width="25%" height="35">&nbsp;</td>
      </tr>
    </table>
  </form>
</body>

</html>