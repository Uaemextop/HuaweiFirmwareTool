<% SendWebHeadStr();%>
<title><% multilang("48" "LANG_GPON_SETTINGS"); %></title>
<script>
function applyclick(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("892" "LANG_TELNET"); %> <% multilang("383" "LANG_SETTINGS"); %></p>
</div>
<form action=/boaform/formTelnetEnable method=POST name="formtelnetEnable">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width=30%><% multilang("892" "LANG_TELNET"); %> <% multilang("568" "LANG_CAPABILITY"); %>:&nbsp;</th>
   <td>
    <input type="radio" value="0" name="telneten" <% checkWrite("telnetenable0"); %>><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
    <input type="radio" value="1" name="telneten" <% checkWrite("telnetenable1"); %>><% multilang("255" "LANG_ENABLE"); %>(<% multilang("6" "LANG_LAN"); %>)
    <input type="radio" value="2" name="telneten" <% checkWrite("telnetenable2"); %>><% multilang("255" "LANG_ENABLE"); %>(<% multilang("6" "LANG_LAN"); %>/<% multilang("11" "LANG_WAN"); %>)
   </td>
  </tr>
  <!--<tr>
   <th width=30%><% multilang("892" "LANG_TELNET"); %> <% multilang("220" "LANG_PORT"); %>:&nbsp;</th>
   <td><input type="text" name="telnetenport" size="20" maxlength="20" value="<% checkWrite("telnetenport"); %>"></td>
  </tr>-->
 </table>
</div>
<div class="btn_ctl clearfix">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return applyclick(this)">&nbsp;&nbsp;
 <input type="hidden" value="/telnet.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
