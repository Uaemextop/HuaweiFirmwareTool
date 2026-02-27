<html>

<head>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    var BinWord = '<%HW_WEB_GetBinMode();%>';
    if (BinWord.toUpperCase() == 'A8C') {
      document.write('<title>中国电信-政企网关</title>');
    } else {
      document.write('<title>中国电信—我的E家</title>');
    }
  </script>
</head>
<style>
  .input_time {
    border: 0px;
  }
</style>
<script type="text/javascript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="javascript">

  var TimerFinish;
  var checkresult;
  var checkhandle;
  var count = 0;
  var fail = 0;
  var IsRhGateway = '<%HW_WEB_GetFeatureSupport(RH_WEB_INFO_DISPLAY);%>'
  var IsLAN = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FT_LAN_UPPORT);%>';

  function check() {
    checkresult = ''

    $.ajax({
      async: true,
      cache: false,
      timeout: 2000,
      type: "POST",
      url: "/asp/GetGrade.asp",
      success: function (data) {
        checkresult = data;
      },
      error: function () {
        checkresult = '';
      },
      complete: function () {
        if ('' == checkresult) {
          fail += 1;
          if (fail > 1) {
            requestrestart();
            return;
          }
        }
        else if (2 == checkresult) {
          count += 1;
          if (count > 3) {
            requestover();
            return;
          }
        }
        else if (3 == checkresult) {
          clearTimeout(TimerFinish);
          document.getElementById("curStatus").innerHTML = "&nbsp终端已启动。";
          document.getElementById("outNotice").innerHTML = "";
          return;
        }
        else if (1 == checkresult) {
          count = 0;
          fail = 0;
        }

        checkhandle = setTimeout(check, 2000);
      }
    });
  }

  function LoadFrame() {
    document.getElementById("curStatus").innerHTML = "&nbsp终端正在进行版本升级，请勿下电。";
    if (1 != IsLAN) {
      document.getElementById("outNotice").innerHTML = "<span style='color:red'>提示：</span></br>ITMS平台正在对设备进行远程升级，且系统启动后自动配置业务（10分钟内），请注意以下几点：</br>1、在升级过程中，不要下电。</br>2、在升级过程中，不要拔插光纤。</br>3、在升级过程中不要关闭该页面。</br>";
    }
    else {
      document.getElementById("outNotice").innerHTML = "<span style='color:red'>提示：</span></br>ITMS平台正在对设备进行远程升级，且系统启动后自动配置业务（10分钟内），请注意以下几点：</br>1、在升级过程中，不要下电。</br>2、在升级过程中不要关闭该页面。</br>";
    }

    TimerFinish = setTimeout(requestover, 400 * 1000);
    check();
  }

  function JumpTo() {
    var opened = window.open('about:blank', '_self');
    opened.opener = null;
    opened.close();
  }

  function requestrestart() {
    document.getElementById("curStatus").innerHTML = "&nbsp终端正在重启，请等待。";
    document.getElementById("outNotice").innerHTML = "";
    clearTimeout(TimerFinish);
    clearTimeout(checkhandle);
    TimerFinish = setTimeout(requestfinish, 120 * 1000);
  }

  function requestover() {
    clearTimeout(TimerFinish);
    clearTimeout(checkhandle);
    document.getElementById("curStatus").innerHTML = "&nbsp终端升级成功，可正常使用业务，谢谢您的耐心等待。";
    document.getElementById("outNotice").innerHTML = "";
    document.getElementById("closebutton").style.display = 'block';
  }

  function requestfinish() {
    clearTimeout(TimerFinish);
    document.getElementById("curStatus").innerHTML = "&nbsp终端升级成功，可正常使用业务，谢谢您的耐心等待。";
    document.getElementById("closebutton").style.display = 'block';
  }

  document.onkeydown = function (event) {
    var theEvent = window.event || event;
    var code = theEvent.keyCode || theEvent.which;
    if (code == 116) {
      theEvent.keyCode ? theEvent.keyCode = 0 : theEvent.which = 0;
      cancelBubble = true;
      if (event && event.preventDefault) {
        event.preventDefault();
      } else {
        window.event.returnValue = false;
      }
      return false;
    }
  }

  document.oncontextmenu = function (e) {
    return false;
  }

</script>

<body onload="LoadFrame();">
  <form>
    <div align="center">

      <TABLE cellSpacing="0" cellPadding="0" width="660" align="center" border="0">

        <TR>
          <TD valign="top" align="right" width="130" height="90"></TD>
        </TR>

        <TD colspan="2" align="center"><span id="curStatus" style="font-size:34px;"></span></TD>

        <TR>
          <TD valign="top" align="right" width="130" height="40"></TD>
        </TR>
        <TD colspan="2" align="left"><span id="outStatus" style="font-size:16px;"></span></TD>
        <TD valign="top" align="right" width="130" height="20"></TD>
        </TR>
        <TD colspan="2" align="left"><span id="outNotice" style="font-size:16px;"></span></TD>

        <TR>
          <TD valign="top" align="right" width="130" height="20"></TD>
        </TR>
        <TR>
          <TD colspan="2" align="center"><input type="button" class="submit" style="font-size: 14px;display:none"
              name="closebutton" id="closebutton" value="关 闭" onclick="JumpTo();" /></TD>
        </TR>
        <TR>
          <TD valign="top" align="right" width="130" height="10"></TD>
        </TR>

        <TR>
          <TD align="center" colSpan="2" width="100%" height="20">
            <font style="font-size: 14px;">中国电信客服热线10000号</font>
          </TD>
        </TR>

        <TR>
          <TD align="left" colSpan="2" height="60"></TD>
        </TR>
      </TABLE>
    </div>
  </form>
</body>

</html>