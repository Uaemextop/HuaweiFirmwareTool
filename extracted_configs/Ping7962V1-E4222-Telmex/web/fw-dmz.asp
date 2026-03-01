<%SendWebHeadStr(); %>
<title>DMZ <% multilang("245" "LANG_CONFIGURATION"); %></title>
<script>
function skip () { this.blur(); }
function saveClick(obj)
{
  if (document.formDMZ.dmzcap[0].checked){
  obj.isclick = 1;
  postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
   }
 if (!checkHostIP(document.formDMZ.ip, 1))
  return false;
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function updateState()
{
  if (document.formDMZ.dmzcap[1].checked) {
  enableTextField(document.formDMZ.ip);
  }
  else {
  disableTextField(document.formDMZ.ip);
  }
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">DMZ <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"><% multilang("428" "LANG_A_DEMILITARIZED_ZONE_IS_USED_TO_PROVIDE_INTERNET_SERVICES_WITHOUT_SACRIFICING_UNAUTHORIZED_ACCESS_TO_ITS_LOCAL_PRIVATE_NETWORK_TYPICALLY_THE_DMZ_HOST_CONTAINS_DEVICES_ACCESSIBLE_TO_INTERNET_TRAFFIC_SUCH_AS_WEB_HTTP_SERVERS_FTP_SERVERS_SMTP_E_MAIL_SERVERS_AND_DNS_SERVERS"); %></p>
</div>
<form action=/boaform/formDMZ method=POST name="formDMZ">
<div class="data_common data_common_notitle">
 <table>
 <tr><th width="30%"><% multilang("429" "LANG_DMZ_HOST"); %>:</th>
       <td width="70%">
  <input type="radio" value="0" name="dmzcap" <% checkWrite("dmz-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
  <input type="radio" value="1" name="dmzcap" <% checkWrite("dmz-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>&nbsp;&nbsp;
       </td>
 </tr>
 <tr>
  <th><% multilang("429" "LANG_DMZ_HOST"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>: </th>
  <td><input type="text" name="ip" size="15" maxlength="15" value=<% getInfo("dmzHost"); %> ></td>
 </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveClick(this)">
 <input type="hidden" value="/fw-dmz.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script> updateState(); </script>
</form>
<br><br>
</body>
</html>
