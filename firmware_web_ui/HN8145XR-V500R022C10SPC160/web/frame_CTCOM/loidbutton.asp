<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <meta http-equiv="Pragma" content="no-cache" />
  <script language="JavaScript" src="../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
  <link rel="stylesheet" href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css'>
  <title>Notice</title>
  <script language="JavaScript" type="text/javascript">

    var simcardstatus = '<%webAspGetSimRegStatus();%>';

    function LoadFrame() {
      if (0 == simcardstatus) {
        document.getElementById('text_tips').innerHTML = "只有插入合法的家庭网关卡后，才能在本页面查看设备注册状态。";
        document.getElementById('btnReboot').disabled = true;
        document.getElementById('btnReboot').style.display = 'none';
      }
      else {
        document.getElementById('icon_image').style.display = 'none';
      }
    }

    function loidconfig() {


      var StepStatus = getCookie('StepStatus');
      if (StepStatus == null || StepStatus == "" || (StepStatus < '0' || StepStatus > '7')) {
        var PrevTime = new Date();
        setCookie("lStartTime", PrevTime);
        setCookie("StepStatus", "0");
        setCookie("CheckOnline", "0");
        setCookie("lastPercent", "0");
      }

      window.location = "/loidresult.asp";
      return;
    }

  </script>
</head>

<body class="mainbody" onLoad="LoadFrame();">
  <div>

    <table width="100%" border="0" cellspacing="0" cellpadding="0">
      <tr>
        <td class="prompt">
          <table width="100%" border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td class='align_left' id="icon_image"><img style="margin-bottom:2px" src="../../images/icon_01.gif"
                  width="15" height="15" /></td>
              <td class="title_01" id="text_tips" style="padding-left:10px;" width="100%">在本页面上，您可以通过点击 "业务配置"
                按钮查看设备注册状态。</td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
    <table width="100%" height="5" border="0" cellpadding="0" cellspacing="0">
      <tr>
        <td></td>
      </tr>
    </table>
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td> <input class="submit" name="btnReboot" id="btnReboot" type='button' onClick='loidconfig()' value="业务配置">
        </td>
      </tr>
    </table>
  </div>
</body>

</html>