<% SendWebHeadStr();%>
<title><% multilang("48" "LANG_GPON_SETTINGS"); %></title>
<script>
var pw_length = <% fmgpon_checkWrite("ploam_pw_length"); %>;
function applyclick(obj)
{
 if (includeSpace(document.formgponconf.fmgpon_loid_password.value)) {
  alert('<% multilang("2260" "LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_LOID_PASSWORD"); %>');
  document.formgponconf.fmgpon_loid_password.focus();
  return false;
 }
 if (checkString(document.formgponconf.fmgpon_loid_password.value) == 0) {
  alert('<% multilang("2261" "LANG_INVALID_LOID_PASSWORD"); %>');
  document.formgponconf.fmgpon_loid_password.focus();
  return false;
 }
 if (document.formgponconf.fmgpon_ploam_password.value=="") {
  alert('<% multilang("2262" "LANG_PLOAM_PASSWORD_CANNOT_BE_EMPTY"); %>');
  document.formgponconf.fmgpon_ploam_password.focus();
  return false;
 }
 if (includeSpace(document.formgponconf.fmgpon_ploam_password.value)) {
  alert('<% multilang("2263" "LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PLOAM_PASSWORD"); %>');
  document.formgponconf.fmgpon_ploam_password.focus();
  return false;
 }
 if (checkString(document.formgponconf.fmgpon_ploam_password.value) == 0) {
  alert('<% multilang("2264" "LANG_INVALID_PLOAM_PASSWORD"); %>');
  document.formgponconf.fmgpon_ploam_password.focus();
  return false;
 }
 if( document.formgponconf.fmgpon_ploam_password.value.length>pw_length )
 {
  alert('<% multilang("2265" "LANG_PLOAM_PASSWORD_SHOULD_BE_10_CHARACTERS"); %>');
  document.formgponconf.fmgpon_ploam_password.focus();
  return false;
 }
 if (document.formgponconf.fmgpon_sn.value=="") {
                alert('<% multilang("2034" "LANG_SERIAL_NUMBER_CANNOT_BE_EMPTY"); %>');
                document.formgponconf.fmgpon_sn.focus();
                return false;
        }
 if (checkStringSpChar(document.formgponconf.fmgpon_sn.value) == 0) {
  alert('<% multilang("2035" "LANG_INVALID_SERIAL_NUMBER") %>');
  document.formgponconf.fmgpon_sn.focus();
  return false;
 }
 if (document.formgponconf.fmgpon_device_type.value=="") {
  alert('<% multilang("541" "LANG_DEVICE_TYPE_CANNOT_BE_EMPTY"); %>');
  document.formgponconf.fmgpon_device_type.focus();
  return false;
        }
 else if (Number(document.formgponconf.fmgpon_device_type.value)<1 || Number(document.formgponconf.fmgpon_device_type.value)>2) {
                alert('<% multilang("542" "LANG_DEVICE_TYPE_CAN_ONLY_BE_EITHER_1_OR_2"); %>');
                document.formgponconf.fmgpon_device_type.focus();
                return false;
        }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function eponmode_config()
{
 var epon = document.getElementById("fmgpon_epon");
 if (true == epon.checked) {
 postTableEncrypt(document.formeponmodeconf.postSecurityFlag, document.formeponmodeconf);
 return true;
 }else {
  alert("You must select the check box");
  return false;
 }
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("48" "LANG_GPON_SETTINGS"); %></p>
 <p class="intro_content"><% multilang("536" "LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_YOUR_GPON_NETWORK_ACCESS"); %></p>
</div>
<form action=/boaform/admin/formgponConf method=POST name="formgponconf">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="40%"><% multilang("537" "LANG_LOID"); %>:</th>
   <td><input type="text" name="fmgpon_loid" size="20" maxlength="20" value="<% fmgpon_checkWrite("fmgpon_loid"); %>"></td>
  </tr>
  <tr>
   <th width="40%"><% multilang("538" "LANG_LOID_PASSWORD"); %>:</th>
   <td><input type="text" name="fmgpon_loid_password" size="20" maxlength="12" value="<% fmgpon_checkWrite("fmgpon_loid_password"); %>"></td>
  </tr>
  <tr>
   <th width="40%"><% multilang("539" "LANG_PLOAM_PASSWORD"); %>:</th>
   <td><input type="text" name="fmgpon_ploam_password" size="36" maxlength="36" value="<% fmgpon_checkWrite("fmgpon_ploam_password"); %>" ></td>
  </tr>
  <tr>
   <th width="40%"><% multilang("540" "LANG_SERIAL_NUMBER"); %>:</th>
   <td><input type="text" name="fmgpon_sn" size="20" maxlength="12" value="<% fmgpon_checkWrite("fmgpon_sn"); %>"></td>
  </tr>
  <tr>
                        <th width="40%"><% multilang("846" "LANG_DEVICE_TYPE"); %>:</th>
                        <td><input type="text" name="fmgpon_device_type" size="20" maxlength="20" value="<% fmgpon_checkWrite("fmgpon_device_type"); %>"></td>
                </tr>
  <% showOMCI_OLT_mode(); %>
 </table>
</div>
<div class="btn_ctl clearfix">
      <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return applyclick(this)">&nbsp;&nbsp;
      <input type="hidden" value="/gpon.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<form action="/boaform/admin/formeponmodeConf" method="POST" name="formeponmodeconf">
<div class="data_common data_common_notitle">
<table>
 <tr>
  <th width="40%"><% multilang("3071" "LANG_EPON_MODE_CONFIG"); %></th>
  <td><input type="checkbox" id="fmgpon_epon" name="fmgpon_epon" value="2"></td>
 </tr>
</table>
</div>
<div class="btn_ctl clearfix">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" onclick="return eponmode_config()">&nbsp;&nbsp;
 <input type="hidden" value="/gpon.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
