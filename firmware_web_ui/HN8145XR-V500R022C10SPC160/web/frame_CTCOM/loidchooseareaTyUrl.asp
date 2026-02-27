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

  #ChooseAreaModule .header {
    font-weight: bold;
    line-height: 18px;
    margin: 0px;
    padding: 0px;
    margin-bottom: 5px;
    text-align: center;
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

  function GetE8CAreaByName(userEthInfos, name) {
    var length = userEthInfos.length;

    for (var i = 0; i < length - 1; i++) {
      if (name == userEthInfos[i].ChineseDes) {
        return userEthInfos[i].E8CArea;
      }
    }

    return null;
  }

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

  var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';

  var CfgFtWordArea = '<%GetConfigAreaInfo();%>';

  var ProvinceArray = '<%GetChoiceProvinceInfo();%>';

  var manageFlag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_CWMP_JSCT);%>';
  var webLoidreg = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_WEB_LOIDREG);%>';
  var MngtGdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_GDCT);%>';
  var MngtFjct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_FJCT);%>';
  var MngtScct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SCCT);%>';
  var MngtCqct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_CQCT);%>';
  var MngtSdct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SDCT);%>';
  var MngtHljct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_HLJCT);%>';
  var Mngtct = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_CT);%>';
  var MngtOnlineJS = '<%HW_WEB_GetFeatureSupport(HW_SSMP_PONONLINE_DISABLEREG);%>';

  var br0Ip = '<%HW_WEB_GetBr0IPString();%>';
  var httpport = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.Services.X_HW_WebServerConfig.ListenInnerPort);%>';
  var CfgFtWord = '<%HW_WEB_GetCfgFtWord();%>';



  if (1 == MngtSdct || 1 == MngtHljct) {
    Mngtct = 1;
  }

  function Submit(type) {
    if (CheckForm(type) == true) {
      var Form = new webSubmitForm();
      AddSubmitParam(Form, type);
      Form.submit();
    }
  }

  function stDevInfo(domain, loid, eponpwd) {
    this.domain = domain;
    this.loid = loid;
    this.eponpwd = eponpwd;
  }

  function stOperateInfo(domain, Result, Status) {
    this.domain = domain;
    this.Result = Result;
    this.Status = Status;
  }

  var stDevInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.DeviceInfo, X_HW_Loid|X_HW_EponPwd, stDevInfo);%>;
  var stDevinfo = stDevInfos[0];

  var stOperateInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_UserInfo, Result|Status, stOperateInfo);%>;
  if (null != stOperateInfos && null != stOperateInfos[0]) {
    var stOperateInfo = stOperateInfos[0];
  }
  else {
    var stResultInfos = new Array(new stOperateInfo("InternetGatewayDevice.X_HW_UserInfo", "99", "99"), null);
    var stOperateInfo = stOperateInfos[0];
  }


  function CheckForm() {
    var loid = getValue('LOIDValue');
    var eponpwd = getValue('PwdValue');

    if ((null == loid) || ('' == loid)) {
      alert("宽带识别码（LOID）不能为空，请输入正确的宽带识别码（LOID）。");
      return false;
    }

    if (!isValidAscii(loid)) {
      alert("宽带识别码（LOID）包含非ASCII字符，请输入正确的宽带识别码（LOID）。");
      return false;
    }

    if (ontPonMode == 'gpon' || ontPonMode == 'GPON') {
      if (loid.length > 24) {
        alert("宽带识别码（LOID）不能超过24个字符。");
        return false;
      }
    }
    else {
      if (loid.length > 32) {
        alert("宽带识别码（LOID）不能超过32个字符。");
        return false;
      }
    }

    if ((null != eponpwd) && ('' != eponpwd)) {
      if (!isValidAscii(eponpwd)) {
        alert("PASSWORD包含非ASCII字符，请输入正确的PASSWORD。");
        return false;
      }

      if (eponpwd.length > 12) {
        alert("PASSWORD不能超过12个字符。");
        return false;
      }
    }

    return true;
  }

  function AddSubmitParam1() {
    if ((((parseInt(Infos.Status) == 0) && (parseInt(Infos.Result) == 1))) && (MngtGdct != 1)) {
      if (MngtScct != 1) {
        window.location = "/loidgregsuccess.asp";
        return;
      }
    }
    if (CheckForm() == true) {
      if (MngtFjct == 1 || MngtScct == 1 || 1 == MngtCqct || Mngtct == 1 || MngtGdct == 1) {
        var PrevTime = new Date();
        setCookie("lStartTime", PrevTime);
        setCookie("StepStatus", "0");
        setCookie("CheckOnline", "0");
        setCookie("lastPercent", "0");
        setCookie("GdTR069WanStatus", "0");
        setCookie("GdDispStatus", "0");
        setCookie("GdTR096WanIp", "0");

      }
      var SubmitForm = new webSubmitForm();

      SubmitForm.addParameter('x.UserName', getValue('LOIDValue'));
      SubmitForm.addParameter('x.UserId', getValue('PwdValue'));
      SubmitForm.addParameter('x.X_HW_Token', getAuthToken());
      if (1 == MngtOnlineJS) {
        SubmitForm.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=loidgregsuccess.asp');
        setDisable('btnApply', 1);
        setDisable('resetValue', 1);
        SubmitForm.submit();
      }
      else {
        SubmitForm.setAction('loid.cgi?' + 'x=InternetGatewayDevice.X_HW_UserInfo&RequestFile=loidresult.asp');
        setDisable('btnApply', 1);
        setDisable('resetValue', 1);
        SubmitForm.submit();
      }
    }
  }

  function AddSubmitParam2() {
    setText('LOIDValue', '');
    setText('PwdValue', '');
  }

  function CheckPwdCancel() {
    window.location = "/login.asp";
  }

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




                    <div id="ChooseAreaModule" class="module" align="justify"
                      style="font-size:8px; display:none; width:410px; height:260px;padding-top:30px; margin-left:-5px;">
                      <p class="header">
                        <font style="font-size: 14px;">请选择所在地区:</font>
                      </p>
                      <input type="button" class="submit_area" name="010" id="010" value="北京" />
                      <input type="button" class="submit_area" name="021" id="021" value="上海" />
                      <input type="button" class="submit_area" name="022" id="022" value="天津" />
                      <input type="button" class="submit_area" name="023" id="023" value="重庆" />
                      <input type="button" class="submit_area" name="0551" id="0551" value="安徽" />
                      <input type="button" class="submit_area" name="0591" id="0591" value="福建" />
                      <input type="button" class="submit_area" name="0931" id="0931" value="甘肃" />
                      <input type="button" class="submit_area" name="020" id="020" value="广东" />
                      <input type="button" class="submit_area" name="0771" id="0771" value="广西" />
                      <input type="button" class="submit_area" name="0851" id="0851" value="贵州" />
                      <input type="button" class="submit_area" name="0898" id="0898" value="海南" />
                      <input type="button" class="submit_area" name="0311" id="0311" value="河北" />
                      <input type="button" class="submit_area" name="0371" id="0371" value="河南" />
                      <input type="button" class="submit_area" name="027" id="027" value="湖北" />
                      <input type="button" class="submit_area" name="0731" id="0731" value="湖南" />
                      <input type="button" class="submit_area" name="0431" id="0431" value="吉林" />
                      <input type="button" class="submit_area" name="025" id="025" value="江苏" />
                      <input type="button" class="submit_area" name="0791" id="0791" value="江西" />
                      <input type="button" class="submit_area" name="024" id="024" value="辽宁" />
                      <input type="button" class="submit_area" name="0951" id="0951" value="宁夏" />
                      <input type="button" class="submit_area" name="0971" id="0971" value="青海" />
                      <input type="button" class="submit_area" name="0531" id="0531" value="山东" />
                      <input type="button" class="submit_area" name="0351" id="0351" value="山西" />
                      <input type="button" class="submit_area" name="029" id="029" value="陕西" />
                      <input type="button" class="submit_area" name="028" id="028" value="四川" />
                      <input type="button" class="submit_area" name="0891" id="0891" value="西藏" />
                      <input type="button" class="submit_area" name="0991" id="0991" value="新疆" />
                      <input type="button" class="submit_area" name="0871" id="0871" value="云南" />
                      <input type="button" class="submit_area" name="0571" id="0571" value="浙江" />
                      <input type="button" class="submit_area" name="0451" id="0451" value="黑龙江" />
                      <input type="button" class="submit_area" name="0471" id="0471" value="内蒙古" />
                    </div>

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

                    <div id="CheckPwdModule" class="module" style="display:none;font-size: 16px;">

                      <p align="center">
                        <font style="font-size: 16px;">输入管理员密码后可选择省份</font>
                      </p>
                      <p align="center">
                        <font style='font-size: 16px;'>验证密码：</font> <input type="password" autocomplete="off"
                          class="input" style="font-size: 14px;" name="CheckPwdValue" id="CheckPwdValue" size="15"
                          maxlength="127" /><strong style="color:#FF0033">*</strong>
                      </p>
                      <font id="CheckPwdPrompt" style="margin-left:20px;display:none;font-size: 13px;" size="2">
                        提示：输入的验证密码不正确，请找支撑经理从ITMS平台获取。</font>
                      <p style="text-align:center;">
                        <br>
                        <input name="btnCheckPwdApply" class="submitApply" id="btnCheckPwdApply"
                          style="font-size: 13px;" type="button" value="&nbsp;确&nbsp;认&nbsp;">
                        <input style="margin-left:20px;font-size: 13px;" 　name="btnCheckPwdCancel" class="submitCancel"
                          id="btnCheckPwdCancel" onClick="CheckPwdCancel();" type="button" value="&nbsp;取&nbsp;消&nbsp;">
                      </p>

                      <script language="javascript">
                        if ('CMCC' == CfgMode.toUpperCase()) {
                          document.write('<p style="text-align:center;"> <font style="font-size: 13px;">中国移动客服热线10086号</font></p>');
                        }
                        else {
                          document.write('<p style="text-align:center;"> <font style="font-size: 13px;">中国电信客服热线10000号</font></p>');
                        }
                      </script>
                    </div>

                    <div id="RegisterModule" class="module" style="display:none;padding-top:55px">
                      <TABLE cellSpacing="0" cellPadding="0" width="400" border="0" height="80%">
                        <tr id="showChooseArea">
                          <td colspan="2" style="text-align:center;">
                            当前配置地区为<span id="SelectedArea"></span>，更改请<a href="#"
                              class="showChooseAreaModule">点击&gt;&gt;</a>
                          </td>
                        </tr>

                        <tr id="tr_pon_type" style="display:none;">
                          <td colspan="2" height="18" align="left" id="pon_type"></td>
                        </tr>

                        <tr>
                          <td colspan="2" align="center" id="ont_sn_des" style="padding-left:30px;"></td>
                        </tr>

                        <tr id="tr_loid_input" style="display:none;height:25px;">
                          <td class="register-input-title" id="ont_loid_value"></td>
                          <td class="register-input-content"><input name="LOIDValue" class="input" id="LOIDValue"
                              style="font-size: 14px;" type="text" size="15" maxlength="63"><strong
                              style="color:#FF0033">*</strong></td>
                        </tr>

                        <tr id="tr_pwd_input" style="display:none;height:25px;">
                          <td class="register-input-title" id="passpwd_value"></td>
                          <td class="register-input-content"><input type="text" class="input" name="PwdValue"
                              id="PwdValue" style="font-size: 14px;" size="15" maxlength="63" /></td>
                        </tr>

                        <tr id="otherinfo" style="display:none;">
                          <td colspan="2" align="center" id="otherinfo_des" style=" "></td>
                        </tr>

                        <script language="javascript">
                          if ('CMCC' == CfgMode.toUpperCase()) {
                            document.write('<TD align="center" colSpan="2" width="100%" height="10"><font style="font-size: 13px;">中国移动客服热线10086号</font></TD>');
                          }
                          else {
                            document.write('<TD align="center" colSpan="2" width="100%" height="20"><font style="font-size: 13px;">中国电信客服热线10000号</font></TD>');
                          }
                        </script>
                  </TR>
                  <TR>
                    <TD align="left" colSpan="2" height="60"></TD>
                  </TR>
              </TABLE>
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
                if ('CMCC' == CfgMode.toUpperCase()) {
                  document.write('<b><font style="font-size: 16px;">此功能仅限移动专业人员使用，普通用户请勿操作</font></b>');
                }
                else {
                  document.write('<b><font style="font-size: 16px;">此功能仅限电信专业人员使用，普通用户请勿操作</font></b>');
                }
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
      window.location = "http://" + br0Ip + ":" + httpport + "/urlloid.asp";

    }

    $(document).ready(function () {
      var viewModel = {
        selectedArea: null,
        $ChooseAreaModule: $('#ChooseAreaModule'),
        $ApplyAreaModule: $('#ApplyAreaModule'),
        $CheckPwdModule: $('#CheckPwdModule'),
        $RegisterModule: $('#RegisterModule')
      };

      viewModel.$ChooseAreaModule.delegate(':button', 'click', function () {

        var area = this.value;

        if (this.disabled) return false;

        viewModel.$ApplyAreaModule.trigger('start', area);

      }).bind({
        start: function (event, backable) {


          viewModel.$ApplyAreaModule.hide();
          viewModel.$RegisterModule.hide();

          viewModel.$ChooseAreaModule.show();

          var gobackBtn = viewModel.$ChooseAreaModule.find('.goback');

          if (backable === "noback") {

            gobackBtn.remove();

          } else {
            if (!gobackBtn.length) {
              viewModel.$ChooseAreaModule.append("<font style='font-size: 14px;'><a class='goback' href='#'>返回&gt;&gt;</a></font>");
            }
          }

          var enabledBtns = ProvinceArray;

          $('.submit_area').filter('[type="button"]').each(function (index) {
            var element = this;
            var name = element.name;
            if (enabledBtns.indexOf) {
              if (enabledBtns.indexOf(name) == -1) {
                $(this).attr('disabled', 'disabled').addClass('disabled');
              }
            } else {
              var included = false;
              $.each(enabledBtns, function (index, item) {
                if (item == name) {
                  included = true;
                  return false;
                }
              });

              if (!included) {
                $(element).attr('disabled', 'disabled').addClass('disabled');
              }
            }

          });

        }
      }).delegate('a.goback', 'click', function (event) {
        event.preventDefault();
        event.stopPropagation();

        window.location = "/login.asp";
      });

      viewModel.$ApplyAreaModule.bind({
        start: function (event, area) {
          var e8cArea;

          if (!area) {
            alert("您未选择任何区域!");
            return;
          }

          if ((parseInt(Infos.Result) == 1) && ((parseInt(Infos.Status) == 0) || (1 == MngtGdct))) {
            alert("已注册成功，请恢复出厂后重新选择所在地区！");
            return;
          }

          e8cArea = GetE8CAreaByName(userEthInfos, area);

          if (confirm("您当前选择的区域为" + area + "，是否进行配置?")) {

            viewModel.$ChooseAreaModule.hide();
            viewModel.$RegisterModule.hide();

            viewModel.$ApplyAreaModule.show();

            DestChooseArea = e8cArea;
            $.post('ConfigE8cArea.cgi?&RequestFile=loidreg.asp', { "AreaInfo": e8cArea, 'x.X_HW_Token': getAuthToken() });

            window.CfgFtWordArea = e8cArea;
            viewModel.$ApplyAreaModule.trigger('beginProgress');

          }
        },
        beginProgress: function () {
          var completeSeconds = 100;
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
              var TimeOutInterval = setTimeout("endProgressJump()", 7000);
            }
          }, 1000);
        }
      });
      viewModel.$CheckPwdModule.bind({
        start: function () {

          viewModel.$ChooseAreaModule.hide();
          viewModel.$ApplyAreaModule.hide();
          viewModel.$RegisterModule.hide();
          viewModel.$CheckPwdModule.show();
        }

      }).delegate('.submitApply', 'click', function (event) {

        var CheckPassword = document.getElementById("CheckPwdValue").value;
        if (CheckPassword == '') {
          alert("输入的密码不能为空！");
          return false;
        }

        var CheckInfo = FormatUrlEncode(CheckPassword);
        var CheckResult = 0;

        $.ajax({
          type: "POST",
          async: false,
          cache: false,
          url: '/asp/CheckModifyInfo.asp?&1=1',
          data: 'CheckInfo=' + CheckInfo,
          success: function (data) {
            CheckResult = data;
          }
        });

        if (1 == CheckResult) {
          viewModel.$CheckPwdModule.hide();
          viewModel.$ChooseAreaModule.trigger('start');
        }
        else {

          document.getElementById('CheckPwdPrompt').style.display = "";
          viewModel.$CheckPwdModule.show();
        }


      });

      viewModel.$RegisterModule.bind({
        start: function () {
          viewModel.$ChooseAreaModule.hide();
          viewModel.$ApplyAreaModule.hide();

          viewModel.$RegisterModule.show();
          viewModel.$RegisterModule.find('#SelectedArea').text(GetE8CAreaByCfgFtWord(userEthInfos, CfgFtWordArea));
        }
      }).delegate('.showChooseAreaModule', 'click', function (event) {

        event.preventDefault();
        event.stopPropagation();
        if (CfgFtWordArea.toUpperCase() != 'NOCHOOSE' && CfgFtWordArea.toUpperCase() != 'CHOOSE') {
          setText('CheckPwdValue', '');
          viewModel.$CheckPwdModule.trigger('start');
        }
        else {
          viewModel.$ChooseAreaModule.trigger('start');
        }
      });

      viewModel.$ApplyAreaModule.hide();
      viewModel.$RegisterModule.hide();
      viewModel.$CheckPwdModule.hide();
      viewModel.$ChooseAreaModule.show();


    });
  </script>
</body>

</html>