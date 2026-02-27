<html>

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <META HTTP-EQUIV="Pragma" CONTENT="no-cache">
  <link rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
  <title>LOID</title>
  <script language="JavaScript" type="text/javascript">
    var JSLoid = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_UserInfo.JSCT_UserName);%>';
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';

    function LoadFrame() {
      document.getElementById('url_loid').style.display = 'none';

      if ('YNCMCC_RMS' == CfgMode.toUpperCase() || 'YNCMCC' == CfgMode.toUpperCase()
        || 'LNCMCC_RMS' == CfgMode.toUpperCase() || 'LNCMCC' == CfgMode.toUpperCase()
        || 'AHCMCC_RMS' == CfgMode.toUpperCase() || 'AHCMCC' == CfgMode.toUpperCase()
        || 'XJCMCC_RMS' == CfgMode.toUpperCase() || 'XJCMCC' == CfgMode.toUpperCase()) {
        SetJSLoid();
      }
      else {
        window.location = "/loidresult.asp";
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


    function SetJSLoid() {
      var jsloid = TextLoidTrans(JSLoid);
      var Form = new webSubmitForm();

      if (jsloid == "") {
        alert("需要烧制的loid不能为空。");
        return false;
      }

      if (24 < jsloid.length) {
        alert("需要烧制的loid长度必须在1到24之间");
        return false;
      }

      if (!(((jsloid.charAt(0) >= '0') && (jsloid.charAt(0) <= '9'))
        || ((jsloid.charAt(0) >= 'A') && (jsloid.charAt(0) <= 'Z'))
        || ((jsloid.charAt(0) >= 'a') && (jsloid.charAt(0) <= 'z')))) {
        alert("loid第一个字符必须是数字（0-9）或字母（a-z,A-Z）。");
        return false;
      }

      if (!(((jsloid.charAt(jsloid.length - 1) >= '0') && (jsloid.charAt(jsloid.length - 1) <= '9'))
        || ((jsloid.charAt(jsloid.length - 1) >= 'A') && (jsloid.charAt(jsloid.length - 1) <= 'Z'))
        || ((jsloid.charAt(jsloid.length - 1) >= 'a') && (jsloid.charAt(jsloid.length - 1) <= 'z')))) {
        alert("loid最后一个字符必须是数字（0-9）或字母（a-z,A-Z）。");
        return false;
      }

      var PrevTime = new Date();
      setCookie("lStartTime", PrevTime);
      setCookie("StepStatus", "0");
      setCookie("CheckOnline", "0");
      setCookie("lastPercent", "0");
      setCookie("GdTR069WanStatus", "0");
      setCookie("GdDispStatus", "0");
      setCookie("GdTR096WanIp", "0");

      Form.addParameter('x.JSCT_UserName', jsloid);
      Form.addParameter('x.UserName', jsloid);
      Form.addParameter('x.X_HW_Token', getAuthToken());
      Form.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo' + '&RequestFile=loidresult.asp');
      Form.submit();
    }


    function CancelConfigLoid() {
      var Form = new webSubmitForm();
      Form.setAction('/');
      Form.submit();
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
                document.write("需要烧制的loid:" + JSLoid);
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