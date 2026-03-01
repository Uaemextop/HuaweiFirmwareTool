<% SendWebHeadStr();%>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<title><% multilang("559" "LANG_PASSWORD_CONFIGURATION"); %></title>
<SCRIPT>
function saveChanges(obj)
{
   if ( document.password.newpass.value != document.password.confpass.value) {
 alert("<% multilang("2086" "LANG_PASSWORD_IS_NOT_MATCHED_PLEASE_TYPE_THE_SAME_PASSWORD_BETWEEN_NEW_AND_CONFIRMED_BOX"); %>");
 document.password.newpass.focus();
 return false;
  }
  if ( document.password.newpass.value.length == 0) {
 alert("<% multilang("2087" "LANG_PASSWORD_CANNOT_BE_EMPTY_PLEASE_TRY_IT_AGAIN"); %>");
 document.password.newpass.focus();
 return false;
  }
  if (includeSpace(document.password.newpass.value)) {
 alert("<% multilang("2090" "LANG_CANNOT_ACCEPT_SPACE_CHARACTER_IN_PASSWORD_PLEASE_TRY_IT_AGAIN"); %>");
 document.password.newpass.focus();
 return false;
  }
  if (checkString(document.password.newpass.value) == 0) {
 alert("<% multilang("2091" "LANG_INVALID_PASSWORD"); %>");
 document.password.newpass.focus();
 return false;
  }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
  return true;
}
</SCRIPT>
</head>
<BODY>
<div class="intro_main ">
 <p class="intro_title"><% multilang("559" "LANG_PASSWORD_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("555" "LANG_PAGE_DESC_SET_ACCOUNT_PASSWORD"); %></p>
</div>
<form action=/boaform/formPasswordSetup method=POST name="password">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="40%"><% multilang("836" "LANG_USER"); %><% multilang("700" "LANG_NAME"); %>:</th>
   <td><select size="1" name="userMode">
    <% checkWrite("userMode"); %>
    </select>
   </td>
  </tr>
  <tr>
   <th><% multilang("556" "LANG_OLD_PASSWORD"); %>:</th>
   <td><input type="password" name="oldpass" size="20" maxlength="30"></td>
  </tr>
  <tr>
   <th><% multilang("557" "LANG_NEW_PASSWORD"); %>:</th>
   <td><input type="password" name="newpass" size="20" maxlength="30"></td>
  </tr>
  <tr>
   <th><% multilang("558" "LANG_CONFIRMED_PASSWORD"); %>:</th>
   <td><input type="password" name="confpass" size="20" maxlength="30"></td>
  </tr>
 </table>
</div>
<div class="btn_ctl clearfix">
 <input type="hidden" value="/password.asp" name="submit-url">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveChanges(this)">&nbsp;&nbsp;
 <input class="link_bg" type="reset" value=" <% multilang("229" "LANG_RESET"); %> " name="reset">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
