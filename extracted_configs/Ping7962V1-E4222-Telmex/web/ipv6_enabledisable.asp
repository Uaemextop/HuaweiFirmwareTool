<%SendWebHeadStr(); %>
<title>IPv6 Enable/Disable</title>
<title><% multilang("458" "LANG_IPV6_E"); %> <% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function on_submit()
{
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</HEAD>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("5" "LANG_IPV6"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"><% multilang("457" "LANG_THIS_PAGE_BE_USED_TO_CONFIGURE_IPV6_ENABLE_DISABLE"); %></p>
</div>
<form id="form" action=/boaform/admin/formIPv6EnableDisable method=POST name="ipv6enabledisable">
<div class="data_common data_common_notitle">
 <table border=0 width="500" cellspacing=4 cellpadding=0>
  <tr>
   <th><% multilang("5" "LANG_IPV6"); %>:</th>
   <td>
    <input type="radio" value="0" name="ipv6switch" <% checkWrite("ipv6enabledisable0"); %> ><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
    <input type="radio" value="1" name="ipv6switch"<% checkWrite("ipv6enabledisable1"); %> ><% multilang("255" "LANG_ENABLE"); %>
   </td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" class="button" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" onClick="return on_submit()">
 <input type="hidden" value="/ipv6_enabledisable.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
