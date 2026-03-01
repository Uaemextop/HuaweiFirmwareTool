<%SendWebHeadStr(); %>
<title>IPIP VPN <% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function checkTextStr(str)
{
 for (var i=0; i<str.length; i++)
 {
  if ( str.charAt(i) == '%' || str.charAt(i) =='&' ||str.charAt(i) =='\\' || str.charAt(i) =='?' || str.charAt(i)=='"')
   return false;
 }
 return true;
}
function ipipSelection()
{
 if (document.ipip.ipipen[0].checked) {
  document.ipip.remote.disabled = true;
  document.ipip.local.disabled = true;
  document.ipip.defaultgw.disabled = true;
  document.ipip.addIPIP.disabled = true;
 }
 else {
  document.ipip.remote.disabled = false;
  document.ipip.local.disabled = false;
  document.ipip.defaultgw.disabled = false;
  document.ipip.addIPIP.disabled = false;
 }
}
function onClickIPIPEnable()
{
 ipipSelection();
 if (document.ipip.ipipen[0].checked)
  document.ipip.lst.value = "disable";
 else
  document.ipip.lst.value = "enable";
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 document.ipip.submit();
}
function addIPIPItf(obj)
{
 if (document.ipip.ipipen[0].checked)
  return false;
 if (!checkHostIP(document.ipip.remote, 1))
 {
  alert('<% multilang("2269" "LANG_INVALID_VALUE_IN_REMOTE_ADDRESS"); %>');
  document.ipip.remote.focus();
  return false;
 }
 if (!checkHostIP(document.ipip.local, 1))
 {
  alert('<% multilang("2270" "LANG_INVALID_VALUE_IN_LOCAL_ADDRESS"); %>');
  document.ipip.local.focus();
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function deleteClick(obj)
{
 if ( !confirm('<% multilang("1753" "LANG_CONFIRM_DELETE_ONE_ENTRY"); %>') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
 }
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">IPIP VPN <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("717" "LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_PARAMETERS_FOR_IPIP_MODE_VPN"); %></p>
</div>
<form action=/boaform/formIPIP method=POST name="ipip">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width=30%>IPIP VPN:</th>
   <td>
    <input type="radio" value="0" name="ipipen" <% checkWrite("ipipenable0"); %> onClick="onClickIPIPEnable()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
    <input type="radio" value="1" name="ipipen" <% checkWrite("ipipenable1"); %> onClick="onClickIPIPEnable()"><% multilang("255" "LANG_ENABLE"); %>
   </td>
  </tr>
 </table>
 <input type="hidden" id="lst" name="lst" value="">
 <table>
  <tr>
   <th width=30%><% multilang("317" "LANG_LOCAL"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td><input type="text" name="local" size="20" maxlength="30"></td>
  </tr>
  <tr>
   <th><% multilang("339" "LANG_REMOTE"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td><input type="text" name="remote" size="20" maxlength="30"></td>
  </tr>
  <tr>
   <th><% multilang("85" "LANG_DEFAULT_GATEWAY"); %>:</th>
   <td><input type="checkbox" name="defaultgw"></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="addIPIP" onClick="return addIPIPItf(this)">&nbsp;&nbsp;
</div>
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p>IPIP <% multilang("337" "LANG_TABLE"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common">
  <table>
   <tr>
    <th><% multilang("233" "LANG_SELECT"); %></th>
    <th><% multilang("700" "LANG_NAME"); %></th>
    <th><% multilang("317" "LANG_LOCAL"); %></th>
    <th><% multilang("339" "LANG_REMOTE"); %></th>
    <th><% multilang("85" "LANG_DEFAULT_GATEWAY"); %></th>
    <th><% multilang("710" "LANG_ACTION"); %></th>
   </tr>
   <% ipipList(); %>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="Delete Selected" name="delSel" onClick="return deleteClick(this)">&nbsp;&nbsp;
 <input type="hidden" value="/ipip.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 ipipSelection();
</script>
</form>
</body>
</html>
