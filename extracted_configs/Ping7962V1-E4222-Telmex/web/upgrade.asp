<% SendWebHeadStr();%>
<title><% multilang("68" "LANG_FIRMWARE_UPGRADE"); %></title>
<script>
function sendClicked()
{
 if (document.password.binary.value=="") {
  alert("<% multilang("2266" "LANG_SELECTED_FILE_CANNOT_BE_EMPTY"); %>");
  document.password.binary.focus();
  return false;
 }
 if (!confirm('<% multilang("565" "LANG_PAGE_DESC_UPGRADE_CONFIRM")%>'))
  return false;
 else
  return true;
}
</script>
</head>
<BODY>
<div class="intro_main ">
 <p class="intro_title"><% multilang("68" "LANG_FIRMWARE_UPGRADE"); %></p>
 <p class="intro_content"> <% multilang("560" "LANG_PAGE_DESC_UPGRADE_FIRMWARE"); %></p>
</div>
<form action=/boaform/admin/formUpload method=POST enctype="multipart/form-data" name="password">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th><input class="inner_btn" type="file" value="<% multilang("546" "LANG_CHOOSE_FILE"); %>" name="binary" size=20></th>
  </tr>
 </table>
</div>
<div class="adsl clearfix">
    <input class="link_bg" type="submit" value="<% multilang("561" "LANG_UPGRADE"); %>" name="send" onclick="return sendClicked()">&nbsp;&nbsp;
 <input class="link_bg" type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset">
 <input type="hidden" value="/admin/upgrade.asp" name="submit-url">
</div>
 </form>
</body>
</html>
