<%SendWebHeadStr(); %>
<title><% multilang("838" "LANG_ACTIVE_DHCP_CLIENTS"); %></title>
<!--<link rel="stylesheet" href="admin/content.css">-->
<SCRIPT>
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("838" "LANG_ACTIVE_DHCP_CLIENTS"); %></p>
 <p class="intro_content"><% multilang("840" "LANG_THIS_TABLE_SHOWS_THE_ASSIGNED_IP_ADDRESS_MAC_ADDRESS_AND_TIME_EXPIRED_FOR_EACH_DHCP_LEASED_CLIENT"); %></p>
</div>
<form action=/boaform/formReflashClientTbl method=POST name="formClientTbl">
<div class="data_common data_vertical">
 <table>
  <tr>
   <th width="30%"><% multilang("89" "LANG_IP_ADDRESS"); %></th>
   <th width="40%"><% multilang("92" "LANG_MAC_ADDRESS"); %></th>
   <th width="30%"><% multilang("169" "LANG_EXPIRED_TIME_SEC"); %></th>
  </tr>
  <% dhcpClientList(); %>
 </table>
</div>
<div class="btn_ctl">
 <input type="hidden" value="/dhcptbl.asp" name="submit-url">
 <input type="submit" value="<% multilang("441" "LANG_REFRESH"); %>" name="refresh" onClick="return on_submit(this)" class="link_bg">&nbsp;&nbsp;
 <input type="button" value="<% multilang("742" "LANG_CLOSE"); %>" name="close" onClick="javascript: window.close();" class="link_bg">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<br><br>
</body>
</html>
