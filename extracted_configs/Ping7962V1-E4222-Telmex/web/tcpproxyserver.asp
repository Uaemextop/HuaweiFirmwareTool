<%SendWebHeadStr(); %>
<title><% multilang("3054" "LANG_TCP_PROXY_SERVER"); %> <% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function checkChange(cb)
{
 if(cb.checked==true){
  cb.value = 1;
 }
 else{
  cb.value = 0;
 }
}
function modeChange()
{
 var mode = document.tcpproxyserver.mode.value;
 document.getElementById("div_server").style.display = "none";
 document.getElementById("server_ip_tr").style.display = "none";
 document.getElementById("server_ip_show_tr").style.display = "none";
 document.getElementById("local_ip_tr").style.display = "none";
 document.getElementById("local_port_tr").style.display = "none";
 if(mode==1){
  document.getElementById("div_server").style.display = "block";
  document.getElementById("server_ip_tr").style.display = "table-row";
  document.getElementById("server_ip_show_tr").style.display = "none";
  document.getElementById("local_ip_tr").style.display = "table-row";
  document.getElementById("local_port_tr").style.display = "table-row";
 }
 else if(mode==2){
  document.getElementById("div_server").style.display = "block";
  document.getElementById("server_ip_tr").style.display = "none";
  document.getElementById("server_ip_show_tr").style.display = "table-row";
  document.getElementById("local_ip_tr").style.display = "none";
  document.getElementById("local_port_tr").style.display = "none";
 }
}
function saveChanges(obj)
{
 if (document.tcpproxyserver.server_port.value=="") {
   alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
   document.tcpproxyserver.server_port.focus();
   return false;
 }
 if ( checkDigit(document.tcpproxyserver.server_port.value) == 0) {
  alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
  document.tcpproxyserver.server_port.focus();
  return false;
 }
 if(document.tcpproxyserver.server_port.value < 1 && document.tcpproxyserver.server_port.value > 65535){
  alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
  document.tcpproxyserver.server_port.focus();
  return false;
 }
 if (document.tcpproxyserver.password.value=="") {
   alert("<% multilang("1839" "LANG_STRPASSEMPTY"); %>");
   document.tcpproxyserver.password.focus();
   return false;
 }
 if (includeSpace(document.tcpproxyserver.password.value)) {
  alert("<% multilang("2887" "LANG_INVALID_PASSWORD_PLEASE_TRY_IT_AGAIN"); %>");
  document.tcpproxyserver.password.focus();
  return false;
 }
 if (checkString(document.tcpproxyserver.password.value) == 0) {
  alert("<% multilang("2887" "LANG_INVALID_PASSWORD_PLEASE_TRY_IT_AGAIN"); %>");
  document.tcpproxyserver.password.focus();
  return false;
 }
 if(document.tcpproxyserver.mode.value==1){
  if (document.tcpproxyserver.server_ip.value=="") {
   alert("<% multilang("1846" "LANG_STRIPADDRESSERROR"); %>");
   document.tcpproxyserver.server_ip.focus();
   return false;
  }
  if (includeSpace(document.tcpproxyserver.server_ip.value)) {
   alert("<% multilang("1845" "LANG_STRINVALIP"); %>");
   document.tcpproxyserver.server_ip.focus();
   return false;
  }
  if (checkString(document.tcpproxyserver.server_ip.value) == 0) {
   alert("<% multilang("1845" "LANG_STRINVALIP"); %>");
   document.tcpproxyserver.server_ip.focus();
   return false;
  }
  if (document.tcpproxyserver.local_port.value=="") {
    alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
    document.tcpproxyserver.local_port.focus();
    return false;
  }
  if ( checkDigit(document.tcpproxyserver.local_port.value) == 0) {
   alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
   document.tcpproxyserver.local_port.focus();
   return false;
  }
  if(document.tcpproxyserver.local_port.value < 1 && document.tcpproxyserver.local_port.value > 65535){
   alert("<% multilang("1986" "LANG_TINVALID_PORT_RANGE"); %>");
   document.tcpproxyserver.local_port.focus();
   return false;
  }
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("3054" "LANG_TCP_PROXY_SERVER"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("3055" "LANG_THIS_PAGE_LET_USER_TO_CONFIG_TCP_PROXY_SERVER"); %></p>
</div>
<form action=/boaform/formTcpproxyserver method=POST name="tcpproxyserver">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("143" "LANG_MODE"); %>:</th>
   <td width="70%">
    <select name="mode" onChange="modeChange()">
     <option value=0><% multilang("353" "LANG_NONE"); %></option>
     <option value=1><% multilang("925" "LANG_PROXY"); %></option>
     <option value=2><% multilang("91" "LANG_SERVER"); %></option>
    </select>
   </td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle" name="div_server" id="div_server" style="display:none">
 <table>
  <tr name="server_ip_tr" id="server_ip_tr" style="display:none">
   <th width="30%"><% multilang("91" "LANG_SERVER"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td width="70%">
    <input type="text" name="server_ip" id="server_ip" size="30" maxlength="128" value="<% ShowTcpproxyserver("server_ip"); %>">
   </td>
  </tr>
  <tr name="server_ip_show_tr" id="server_ip_show_tr" style="display:none">
   <th width="30%"><% multilang("91" "LANG_SERVER"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td width="70%">
    any
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("91" "LANG_SERVER"); %> <% multilang("220" "LANG_PORT"); %>:</th>
   <td width="70%">
    <input type="text" name="server_port" id="server_port" size="30" maxlength="30" value="<% ShowTcpproxyserver("server_port"); %>">
   </td>
  </tr>
  <tr name="local_ip_tr" id="local_ip_tr" style="display:none">
   <th width="30%"><% multilang("317" "LANG_LOCAL"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td width="70%">
    any
   </td>
  </tr>
  <!--
  <tr name="local_ip_tr" id="local_ip_tr" style="display:none">
   <th width="30%"><% multilang("317" "LANG_LOCAL"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:</th>
   <td width="70%">
    <input type="text" name="local_ip" id="local_ip" size="30" maxlength="128" value="<% ShowTcpproxyserver("local_ip"); %>">
   </td>
  </tr>
  -->
  <tr name="local_port_tr" id="local_port_tr" style="display:none">
   <th width="30%"><% multilang("317" "LANG_LOCAL"); %> <% multilang("220" "LANG_PORT"); %>:</th>
   <td width="70%">
    <input type="text" name="local_port" id="local_port" size="30" maxlength="30" value="<% ShowTcpproxyserver("local_port"); %>">
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("67" "LANG_PASSWORD"); %>:</th>
   <td width="70%">
    <input type="password" name="password" id="password" size="30" maxlength="128" value="<% ShowTcpproxyserver("password"); %>">
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("208" "LANG_ENCRYPTION"); %>:</th>
   <td width="70%">
    <select name="encryption">
     <% ShowTcpproxyserver("encryption"); %>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3056" "LANG_REUSEPORT"); %>:</th>
   <td width="70%"><input type="checkbox" name="reuseport" onChange="checkChange(this)" <% ShowTcpproxyserver("reuseport"); %>></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3057" "LANG_FASTOPEN"); %>:</th>
   <td width="70%"><input type="checkbox" name="fastopen" onChange="checkChange(this)" <% ShowTcpproxyserver("fastopen"); %>></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3058" "LANG_NODELAY"); %>:</th>
   <td width="70%"><input type="checkbox" name="nodelay" onChange="checkChange(this)" <% ShowTcpproxyserver("nodelay"); %>></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type=submit value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveChanges(this)">
      <input type=hidden value="/tcpproxyserver.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% ShowTcpproxyserver("mode"); %>
 modeChange();
</script>
</form>
</body>
</html>
