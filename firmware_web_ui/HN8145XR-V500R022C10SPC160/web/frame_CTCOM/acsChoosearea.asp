<!DOCTYPE html>
<html>

<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <script language="JavaScript" type="text/javascript">
    var CfgMode = '<%HW_WEB_GetCfgMode();%>';
    if ('CMCC' == CfgMode.toUpperCase()) {
      document.write('<title>中国移动</title>');
    }
    else {
      document.write('<title>中国电信—我的E家</title>');
    }
  </script>
  <META http-equiv=Content-Type content="text/html; charset=UTF-8">
  <meta http-equiv="Pragma" content="no-cache" />
</head>
<script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(md5.js);%>"></script>
<script language="JavaScript"
  src="/../../resource/common/<%HW_WEB_CleanCache_Resource(RndSecurityFormat.js);%>"></script>
<script type="text/javascript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>

<style type="text/css">
  .register-input {}

  .guangdong {
    width: 430px;
    font-size: 14px;
  }

  .qita {
    width: 400px;
  }

  .register-input tr {
    width: 100%;
  }

  .guangdong .register-input-title {
    width: 170px;

  }


  .guangdong .register-input-content {
    width: 260px;
  }

  .qita .register-input-title {
    width: 130px;
  }

  .qita .register-input-content {
    width: 270px;
  }

  .register-input-title {
    text-align: right;
  }

  .register-input-content .input {
    width: 150px;
    margin-left: 2em;
  }

  .input_time {
    border: 0px;
  }

  .submit_area {
    font: 12px Arial, ËÎÌå;
    color: #0000FF;
    height: 25px;
    width: 60px;
    margin-left: 2px;
    margin-bottom: 4px;

    background-color: #E1E1E1;
    display: inline-block;
  }

  .disabled {
    color: gray;
  }

  .goback {
    display: inline-block;
    padding-left: 4px;
    margin: 0px;
    height: 25px;
    color: red;
  }


  .content {
    width: 653px;
    height: 323px;
    position: absolute;
  }

  .content .prompt {
    position: absolute;
    top: 0px;
    left: 0px;
    width: 96%;
    height: 40px;
    ;
    border: 0px;
  }

  .content .module {
    position: absolute;
    top: 55px;
    left: 110px;
    width: 430px;
  }

  #SelectedArea {
    color: Red;
    font-weight: bold;
  }

  .progress {
    position: relative;
    left: 10px;
    background-color: white;
    width: 380px;
    height: 20px;
  }

  .progress .progressbar {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 0%;
    height: 18px;
    background-color: orange;
  }

  .progress .progress-text {
    position: absolute;
    top: 1px;
    left: 1px;
    width: 378px;
    height: 16px;
    color: Black;
    text-align: center;
    font-size: 12px;
  }
</style>
<script type="text/javascript">
  var ctcomHostIpAddress = '<%HW_WEB_GetSPEC(SPEC_CTCOM_HOST_IPADDESS.STRING);%>';

  function stResultInfo(domain, Result, Status) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
  }

  function AreaRelationInfo(ChineseDes, E8CArea) {
    this.ChineseDes = ChineseDes;
    this.E8CArea = E8CArea;
  }

  var DestChooseArea;

  var userEthInfos = new Array(new AreaRelationInfo("重庆", "023"),
    new AreaRelationInfo("四川", "028"),
    new AreaRelationInfo("云南", "0871"),
    new AreaRelationInfo("贵州", "0851"),
    new AreaRelationInfo("北京", "010"),
    new AreaRelationInfo("上海", "021"),
    new AreaRelationInfo("天津", "022"),
    new AreaRelationInfo("安徽", "0551"),
    new AreaRelationInfo("福建", "0591"),
    new AreaRelationInfo("甘肃", "0931"),
    new AreaRelationInfo("广东", "020"),
    new AreaRelationInfo("广西", "0771"),
    new AreaRelationInfo("海南", "0898"),
    new AreaRelationInfo("河北", "0311"),
    new AreaRelationInfo("河南", "0371"),
    new AreaRelationInfo("湖北", "027"),
    new AreaRelationInfo("湖南", "0731"),
    new AreaRelationInfo("吉林", "0431"),
    new AreaRelationInfo("江苏", "025"),
    new AreaRelationInfo("苏州", "0512"),
    new AreaRelationInfo("江西", "0791"),
    new AreaRelationInfo("辽宁", "024"),
    new AreaRelationInfo("宁夏", "0951"),
    new AreaRelationInfo("青海", "0971"),
    new AreaRelationInfo("山东", "0531"),
    new AreaRelationInfo("山西", "0351"),
    new AreaRelationInfo("陕西", "029"),
    new AreaRelationInfo("西藏", "0891"),
    new AreaRelationInfo("新疆", "0991"),
    new AreaRelationInfo("浙江", "0571"),
    new AreaRelationInfo("黑龙江", "0451"),
    new AreaRelationInfo("内蒙古", "0471"),
    null);

  function GetE8CAreaByCfgFtWord(userEthInfos, name) {
    var length = userEthInfos.length;

    for (var i = 0; i < length - 1; i++) {
      if (name == userEthInfos[i].E8CArea) {
        return userEthInfos[i].ChineseDes;
      }
    }

    return null;
  }

  var stResultInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stResultInfo);%>;
  if (null != stResultInfos && null != stResultInfos[0]) {
    var Infos = stResultInfos[0];
  }
  else {
    var stResultInfos = new Array(new stResultInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99", "10", "0", "NONE", "1", ""), null);
    var Infos = stResultInfos[0];
  }

  var CfgFtWordArea = '<%GetConfigAreaInfo();%>';

  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';

  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';

</script>

<body>
  <form>
    <div align="center">
      <table cellSpacing="0" cellPadding="0" width="808" align="center" border="0">
        <TBODY>
          <TR>
            <script language="JavaScript" type="text/javascript">
              if ('CMCC' == CfgMode.toUpperCase()) {
                document.write('<TD ><IMG height="137" src="/images/register_banner_cmcc.jpg" width="808"></TD> ');
              }
              else {
                document.write('<TD ><IMG height="137" src="/images/register_banner.jpg" width="808"></TD> ');
              }
            </script>
          </TR>
          <TR>
            <TD>
              <table width="808" height="323" border="0" align="center" cellpadding="0" cellspacing="0"
                style="margin-top: -5px;">
                <TBODY>
                  <TR>
                    <TD width="77" background="/images/bg.gif" rowSpan="3"></TD>
                    <script language="javascript">
                      document.write('<TD  align="center" width="653" height="323" background="/images/register_gdinfo.jpg">');

                    </script>

                    <div id="ApplyAreaModule" class="module" style="display:none;padding-top:50px">


                      <div class="progress">
                        <div class="progressbar">
                          <div class="progress-text">0%</div>
                        </div>
                      </div>
                      <p id="RedirectText" style="text-align:center; height:220px; font-size: 16px;"></p>

                      <script type="text/javascript">
                        $('#ApplyAreaModule').children('table')
                          .addClass('register-input')
                          .addClass((MngtGdct == 1 ? 'guangdong' : 'qita'));
                      </script>
                    </div>

    <TD width="78" background="/images/bg.gif" rowSpan="3"></TD>
    </TR>
    </TBODY>
    </TABLE>
    </TD>
    </TR>
    </TBODY>
    </TABLE>
    </div>

    <div align="center" style="margin-top:-320px">
      <table class="prompt">
        <TR>
          <TD width="12%"></TD>
          <TD align="center" width="7%"><img height="40" src="/images/icon_01.gif" width="40"></TD>
          <TD valign="middle" width="65%">
            <font style="font-size: 16px;">
              <script language="JavaScript" type="text/javascript">
                document.write('<b><font style="font-size: 16px;">此功能仅限电信专业人员使用，普通用户请勿操作</font></b>');
              </script>
          </TD>
          <TD align="right" width="20%">
            <script language="javascript">
              document.write('<A href="http://' + br0Ip + ':' + httpport + '/login.asp"><font style="font-size: 13px;" color="#000000">返回登录页面</FONT></A>');
            </script>
          </TD>

        </TR>
      </TABLE>
    </div>

  </form>
  <script type="text/javascript">
    var regHW = "";
    function endProgressJump() {
      if (window.location.host.indexOf(br0Ip) > -1) {
        if (regHW == "DONEHW") {
          window.location = "http://" + br0Ip + ":" + httpport + "/loidreg.asp";
        }
        else {
          if (DestChooseArea == "022") {
            window.location = "http://" + br0Ip;
          }
          else {
            window.location = ctcomHostIpAddress;
          }
        }
      } else {

        if (regHW == "DONEHW") {
          window.location = "http://" + br0Ip + ":" + httpport + "/loidreg.asp";
        }
        else {
          if (DestChooseArea == "022") {
            window.location = "http://" + br0Ip;
          }
          else {
            window.location = 'http://' + window.location.host;
          }
        }
      }
    }

    $(document).ready(function () {
      var viewModel = {
        selectedArea: null,
        $ApplyAreaModule: $('#ApplyAreaModule')
      };

      viewModel.$ApplyAreaModule.bind({
        start: function (event) {
          viewModel.$ApplyAreaModule.show();

          viewModel.$ApplyAreaModule.trigger('beginProgress');
        },
        beginProgress: function () {
          var completeSeconds = 50;
          var startSeconds = 0;
          var startTime = new Date();
          var endTime = new Date();

          viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置" + GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea) + "，请勿断电...");
          viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));

          var interval = setInterval(function () {

            if (startSeconds != completeSeconds) {
              var configstatus = '';

              $.ajax({
                type: "POST",
                async: true,
                cache: false,
                url: "/asp/GetConfigStatusInfo.asp",
                success: function (data) {
                  configstatus = data;
                },
                error: function () {
                  configstatus = '';
                },

                complete: function () {
                  if (configstatus == '') {
                    if (parseInt((endTime.getTime() - startTime.getTime()) / 1000) > 40) {
                      viewModel.$ApplyAreaModule.find('#RedirectText').text("设备网络连接可能已断开，请检查你的网络连接状态。");
                    }
                  }
                  else if (configstatus == "DONE") {
                    viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置" + GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea) + "，请勿断电...");
                    startSeconds = completeSeconds;
                  }
                  else if (configstatus == "DONEHW") {
                    viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置" + GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea) + "，请勿断电...");
                    startSeconds = completeSeconds;
                    regHW = "DONEHW";
                  }
                  else if (parseInt((startSeconds / completeSeconds) * 100) > 99) {
                    viewModel.$ApplyAreaModule.find('#RedirectText').text("请稍候，正在配置" + GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea) + "，请勿断电...");
                    viewModel.$ApplyAreaModule.trigger('setProgress', 100);//装维人员需要速度。
                    startSeconds = completeSeconds;
                  }
                  else if (configstatus == "DOING" || configstatus == "NOTDO") {
                    viewModel.$ApplyAreaModule.trigger('setProgress', parseInt((startSeconds / completeSeconds) * 100));
                    if (startSeconds < 98) {
                      startSeconds += 1.3;
                    }

                  }
                  endTime = new Date();
                }
              });
            } else {

              viewModel.$ApplyAreaModule.trigger('setProgress', 100);

              viewModel.$ApplyAreaModule.trigger('endProgress');

              clearInterval(interval);

            };

          }, 1000);
        },
        setProgress: function (event, percent) {
          viewModel.$ApplyAreaModule.find('.progressbar').css('width', percent + '%');
          viewModel.$ApplyAreaModule.find('.progress-text').text(percent + '%');
        },
        endProgress: function () {

          redirectSeconds = 1;

          var tempInterval = setInterval(function () {

            if (redirectSeconds !== 0) {
              redirectSeconds -= 1;
            }
            else {
              clearInterval(tempInterval);
              var TimeOutInterval = setTimeout("endProgressJump()", 2000);
            }
          }, 1000);
        }
      });

      viewModel.$ApplyAreaModule.show();
      viewModel.$ApplyAreaModule.trigger('start');

    });
  </script>
</body>

</html>