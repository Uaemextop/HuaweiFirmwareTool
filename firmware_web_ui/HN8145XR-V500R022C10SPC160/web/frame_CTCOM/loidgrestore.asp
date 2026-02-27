<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    var BinWord = '<%HW_WEB_GetBinMode();%>';
    if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
      document.write('<title>中国移动</title>');
    } else if (BinWord.toUpperCase() == 'A8C') {
      document.write('<title>中国电信—政企网关</title>');
    }
    else {
      document.write('<title>中国电信—我的E家</title>');
    }
  </script>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">

  <script language="JavaScript"
    src="/../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
</head>
<style>
  .input_time {
    border: 0px;
  }
</style>
<script language="javascript">

  var Language = "chinese";
  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';

  function stResultInfo(domain, Result, Status, Limits, Times, RegTimerState, InformStatus, ProvisioningCode, ServiceNum) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
  var SuccInfos = stResultInfos[0];

  function isValidAscii(val) {
    for (var i = 0; i < val.length; i++) {
      var ch = val.charAt(i);
      if (ch < ' ' || ch > '~') {
        return false;
      }
    }
    return true;
  }

  document.onkeypress = function (e) {
    var charCode;
    if (window.event) {
      e = window.event;
      charCode = (e.type == "keypress") ? e.keyCode : 0;
    }
    else {
      charCode = e.which;
    }
    if (charCode == 13) {
      return false;
    }
  }


  function Submit(type) {
    if (CheckForm(type) == true) {
      var Form = new webSubmitForm();
      AddSubmitParam(Form, type);
      Form.submit();
    }
  }


  function LoadFrame() {
    if ((parseInt(SuccInfos.Status) == 0) && (parseInt(SuccInfos.Result) == 1)) {
      document.getElementById('restoreshow').style.display = "";
    }
    else {
      if ((CfgMode.toUpperCase() == 'SCCT') || (CfgMode.toUpperCase() == 'SCSCHOOL') || (CfgMode.toUpperCase() == 'SCCT_FTTO')) {
        document.getElementById('restoreshow').style.display = "";
      }
      else {
        window.location = "/login.asp";
      }
    }

  }

  function AddSubmitParam1() {
    var Password = document.getElementById('PwdValue');
    var appName = navigator.appName;
    var version = navigator.appVersion;

    if (appName == "Microsoft Internet Explorer") {
      var versionNumber = version.split(" ")[3];
      if (parseInt(versionNumber.split(";")[0]) < 6) {
        alert("不支持IE6.0以下版本。");
        return;
      }
    }

    if (Password.value == "") {
      alert("密码不能为空。");
      Password.focus();
      return false;
    }
    if (!isValidAscii(Password.value)) {
      alert("密码包含非法字符。");
      Password.focus();
      return false;
    }

    Password.disabled = true;

    var Form = new webSubmitForm();
    Form.addParameter('passwd', Password.value);
    Form.addParameter('x.X_HW_Token', getAuthToken());
    Form.setAction('fjrestoredcfg.cgi?RequestFile=loidgrestoresuccess.html');
    Form.submit();
  }

  function AddSubmitParam2() {

    window.location = "/login.asp";
  }
</script>

<body onLoad="LoadFrame();">
  <form>
    <div align="center" id="restoreshow" style="display:none">
      <TABLE cellSpacing="0" cellPadding="0" width="808" align="center" border="0">
        <TBODY>
          <TR>
            <script language="JavaScript" type="text/javascript">
              if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                document.write('<TD ><IMG height="137" src="/images/register_banner_cmcc.jpg" width="808"></TD> ');
              }
              else {
                document.write('<TD ><IMG height="137" src="/images/register_banner.jpg" width="808"></TD>');
              }
            </script>

          </TR>
          <TR>
            <TD>
              <TABLE cellSpacing="0" cellPadding="0" align="middle" width="808" border="0"
                style="position: relative; margin-top: -5px;">
                <TBODY>
                  <TR>
                    <TD width="77" background="/images/bg.gif" rowSpan="3"></TD>
                    <TD align="center" width="653" height="323" background="/images/register_gdinfo.jpg">
                      <TABLE cellSpacing="0" cellPadding="0" width="96%" height="15%" border="0">
                        <TR>
                          <TD align="right">
                            <script language="javascript">
                              document.write('<A href="http://' + br0Ip + ':' + httpport + '/login.asp"><font style="font-size: 14px;" color="#000000">返回登录页面</FONT></A>');
                            </script>
                          </TD>
                        </TR>
                      </TABLE>
                      <script language="javascript">
                        document.write('<TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">');
                      </script>
                    <TD colSpan="2" height="20"></TD>
                    <script language="javascript">
                      document.write('<TR><TD align="center" colSpan="2" height="25"><font style="font-size: 16px;">输入正确验证码，可以帮助恢复默认的出厂配置</font></TD></TR>');
                      document.write('<TR>');
                      document.write('<TD valign="bottom" align="right" width="130" height="25" ><font style="font-size: 16px;">验证密码：</font></TD>');
                      document.write('<TD valign="bottom" align="left" width="130"><input name="PwdValue" id="PwdValue" type="password" autocomplete="off" size="15" maxlength="127"><strong style="color:#FF0033">*</strong></TD>');
                      document.write('</TR>');

                    </script>
                  <TR height="8">
                    <TD align="center" colSpan="2" height="35">
                      <input name="btnApply" class="submit" id="setReg" onClick="AddSubmitParam1()" type="button"
                        value="&nbsp;提&nbsp;交&nbsp;">
                      <span style="margin-left:60px" />
                      <input name="resetValue" id="resetValue" type="button" class="submit" onClick="AddSubmitParam2();"
                        value="&nbsp;取&nbsp;消&nbsp;">
                    </TD>
                  </TR>
                  <TR>
                    <script language="JavaScript" type="text/javascript">
                      if (('CMCC' == CfgMode.toUpperCase()) || ('JSCMCC' == CfgMode.toUpperCase())) {
                        document.write('<TD align="center" colSpan="2" width="100%" height="20"><font style="font-size: 14px;">中国移动客服热线10086号</font></TD>');
                      }
                      else {
                        document.write('<TD align="center" colSpan="2" width="100%" height="20"><font style="font-size: 14px;">中国电信客服热线10000号</font></TD>');
                      }
                    </script>

                  </TR>
                  <TR>
                    <TD align="left" colSpan="2" height="60"></TD>
                  </TR>
              </TABLE>
            <TD width="78" background="/images/bg.gif" rowSpan="3"></TD>
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