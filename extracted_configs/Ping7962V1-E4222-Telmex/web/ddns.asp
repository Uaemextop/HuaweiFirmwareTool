<%SendWebHeadStr(); %>
<META HTTP-EQUIV=Refresh CONTENT="60; URL=ddns.asp">
<title><% multilang("379" "LANG_DYNAMIC"); %> DNS <% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
selected=0;
function deSelected()
{
}
function btnClick()
{
 if (document.ddns.hostname.value=="") {
  alert('<% multilang("2110" "LANG_PLEASE_ENTER_HOSTNAME_FOR_THIS_ACCOUNT"); %>');
  document.ddns.hostname.focus();
  deSelected();
  return false;
 }
 if (includeSpace(document.ddns.hostname.value)) {
  alert('<% multilang("2111" "LANG_INVALID_HOST_NAME"); %>');
  document.ddns.hostname.focus();
  return false;
 }
 if (checkString(document.ddns.hostname.value) == 0) {
  alert('<% multilang("2111" "LANG_INVALID_HOST_NAME"); %>');
  document.ddns.hostname.focus();
  return false;
 }
 if (document.ddns.ddnsProv.value=="0") {
  if (document.ddns.username.value=="") {
   alert('<% multilang("2112" "LANG_PLEASE_ENTER_USERNAME_FOR_THIS_ACCOUNT"); %>');
   document.ddns.username.focus();
   deSelected();
   return false;
  }
  if (includeSpace(document.ddns.username.value)) {
   alert('<% multilang("2089" "LANG_INVALID_USER_NAME"); %>');
   document.ddns.username.focus();
   return false;
  }
  if (checkString(document.ddns.username.value) == 0) {
   alert('<% multilang("2089" "LANG_INVALID_USER_NAME"); %>');
   document.ddns.username.focus();
   return false;
  }
  if (document.ddns.password.value=="") {
   alert('<% multilang("2113" "LANG_PLEASE_ENTER_PASSWORD_FOR_THIS_ACCOUNT"); %>');
   document.ddns.password.focus();
   deSelected();
   return false;
  }
    if ( includeSpace(document.ddns.password.value)) {
   alert('<% multilang("2091" "LANG_INVALID_PASSWORD"); %>');
   document.ddns.password.focus();
   return false;
   }
  if (checkString(document.ddns.password.value) == 0) {
   alert('<% multilang("2091" "LANG_INVALID_PASSWORD"); %>');
   document.ddns.password.focus();
   return false;
  }
 }
 if (document.ddns.ddnsProv.value=="1") {
  if (document.ddns.email.value=="") {
   alert('<% multilang("2114" "LANG_PLEASE_ENTER_EMAIL_FOR_THIS_ACCOUNT"); %>');
   document.ddns.email.focus();
   deSelected();
   return false;
  }
  if (includeSpace(document.ddns.email.value)) {
   alert('<% multilang("2115" "LANG_INVALID_EMAIL"); %>');
   document.ddns.email.focus();
   return false;
  }
  if (checkString(document.ddns.email.value) == 0) {
   alert('<% multilang("2115" "LANG_INVALID_EMAIL"); %>');
   document.ddns.email.focus();
   return false;
  }
  if (document.ddns.key.value=="") {
   alert('<% multilang("2116" "LANG_PLEASE_ENTER_KEY_FOR_THIS_ACCOUNT"); %>');
   document.ddns.key.focus();
   deSelected();
          return false;
         }
  if (includeSpace(document.ddns.key.value)) {
   alert('<% multilang("2117" "LANG_INVALID_KEY"); %>');
   document.ddns.key.focus();
   return false;
  }
  if (checkString(document.ddns.key.value) == 0) {
   alert('<% multilang("2117" "LANG_INVALID_KEY"); %>');
   document.ddns.key.focus();
   return false;
  }
 }
 return true;
}
function addClick()
{
 if(btnClick())
 {
  document.forms[0].addacc.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
 }
 else
  return false;
}
function modifyClick()
{
 if (!selected) {
  alert('<% multilang("2118" "LANG_PLEASE_SELECT_AN_ENTRY_TO_MODIFY"); %>');
  return false;
 }
 if(btnClick())
 {
  document.forms[0].modify.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
 }
 else
  return false;
}
function removeClick()
{
 if (!selected) {
  alert('<% multilang("2119" "LANG_PLEASE_SELECT_AN_ENTRY_TO_DELETE"); %>');
  return false;
 }
 document.forms[0].delacc.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function updateState()
{
  if (document.ddns.ddnsProv.value=="0" || document.ddns.ddnsProv.value=="2") {
  enableTextField(document.ddns.username);
  enableTextField(document.ddns.password);
  disableTextField(document.ddns.email)
  disableTextField(document.ddns.key)
  }
  else {
   enableTextField(document.ddns.email);
   enableTextField(document.ddns.key);
  disableTextField(document.ddns.username);
  disableTextField(document.ddns.password);
  }
}
function postEntry(enabled, pvd, host, user, passwd, intf)
{
 if (enabled)
  document.ddns.enable.checked = true;
 else
  document.ddns.enable.checked = false;
 document.ddns.hostname.value = host;
 if (pvd == 'dyndns') {
  document.ddns.ddnsProv.value = 0;
  document.ddns.username.value = user;
  document.ddns.password.value = passwd;
  document.ddns.email.value = '';
  document.ddns.key.value = '';
  document.ddns.interface.value = intf;
 }
  else if (pvd == 'noip') {
  document.ddns.ddnsProv.value = 2;
  document.ddns.username.value = user;
  document.ddns.password.value = passwd;
  document.ddns.email.value = '';
  document.ddns.key.value = '';
  document.ddns.interface.value = intf;
 }
 else {
  document.ddns.ddnsProv.value = 1;
  document.ddns.username.value = '';
  document.ddns.password.value = '';
  document.ddns.email.value = user;
  document.ddns.key.value = passwd;
  document.ddns.interface.value = intf;
 }
 updateState();
 selected = 1;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("379" "LANG_DYNAMIC"); %> DNS <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"><% multilang("380" "LANG_PAGE_DESC_CONFIGURE_DYNAMIC_DNS_ADDRESS"); %></p>
</div>
<form action=/boaform/formDDNS method=POST name="ddns">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("255" "LANG_ENABLE"); %>:</th>
   <td width="70%"><input type="checkbox" name="enable" value="1" checked></td>
  </tr>
  <tr>
   <th width="30%">DDNS <% multilang("381" "LANG_PROVIDER"); %>:</th>
   <td width="70%">
    <select size="1" name="ddnsProv" onChange='updateState()'>
     <option selected value="0">DynDNS.org</option>
     <option value="1">TZO</option>
     <option value="2">No-IP</option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("382" "LANG_HOSTNAME"); %>:</th>
   <td width="70%"><input type="text" name="hostname" size="35" maxlength="35"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("70" "LANG_INTERFACE"); %></th>
   <td width="70%">
    <select name="interface" >
      <% if_wan_list("rt");%>
    <!--<option value=100>LAN/br0</option>-->
    </select>
   </td>
  </tr>
 </table>
</div>
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p>DynDns <% multilang("383" "LANG_SETTINGS"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common">
  <table>
   <tr>
    <th width="30%"><% multilang("836" "LANG_USER"); %><% multilang("700" "LANG_NAME"); %>:</th>
    <td width="70%"><input type="text" name="username" size="35" maxlength="35"></td>
   </tr>
   <tr>
    <th width="30%"><% multilang("67" "LANG_PASSWORD"); %>:</th>
    <td width="70%"><input type="password" name="password" size="35" maxlength="35"></td>
   </tr>
  </table>
 </div>
</div>
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p>TZO <% multilang("383" "LANG_SETTINGS"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common">
  <table>
   <tr>
    <th width="30%"><% multilang("384" "LANG_EMAIL"); %>:</th>
    <td width="70%"><input type="text" name="email" size="35" maxlength="35"></td>
   </tr>
   <tr>
    <th width="30%"><% multilang("250" "LANG_KEY"); %>:</th>
    <td width="70%"><input type="password" name="key" size="35" maxlength="35"></td>
   </tr>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <!--<input type="hidden" name="interface" value="all">-->
 <input type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addacc" onClick="return addClick()" class="link_bg">
 <input type="submit" value="<% multilang("338" "LANG_MODIFY"); %>" name="modify" onClick="return modifyClick()" class="link_bg">
 <input type="submit" value="<% multilang("385" "LANG_REMOVE"); %>" name="delacc" onClick="return removeClick()" class="link_bg">
</div>
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p><% multilang("379" "LANG_DYNAMIC"); %> DNS <% multilang("422" "LANG__TABLE"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common data_vertical">
  <table>
   <% showDNSTable(); %>
  </table>
  <input type="hidden" value="/ddns.asp" name="submit-url">
  <input type="hidden" name="postSecurityFlag" value="">
   </div>
</div>
<script>
 updateState();
 deSelected();
</script>
</form>
<br><br>
</body>
</html>
