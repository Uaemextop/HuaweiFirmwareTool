<%SendWebHeadStr(); %>
<title><% multilang("35" "LANG_ARP_TABLE"); %></title>
<SCRIPT>
function on_submit()
{
 document.forms[0].refresh.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("442" "LANG_USER_LIST"); %></p>
 <p class="intro_content"><% multilang("439" "LANG_PAGE_DESC_MAC_TABLE_INFO"); %></p>
</div>
<form action=/boaform/formRefleshFdbTbl method=POST name="formFdbTbl">
 <div class="data_common data_common_notitle data_vertical">
  <table>
   <tr>
    <th width="40%"><% multilang("89" "LANG_IP_ADDRESS"); %></th>
    <th width="60%"><% multilang("92" "LANG_MAC_ADDRESS"); %></th>
   </tr>
   <% ARPTableList(); %>
  </table>
 </div>
 <div class="btn_ctl">
  <input type="hidden" value="/arptable.asp" name="submit-url">
  <input class="link_bg" type="submit" value="<% multilang("441" "LANG_REFRESH"); %>" name="refresh" onClick="return on_submit()">&nbsp;&nbsp;
  <input type="hidden" name="postSecurityFlag" value="">
 </div>
</form>
<br><br>
</body>
</html>
