<%SendWebHeadStr(); %>
<title>WDS AP <% multilang("337" "LANG_TABLE"); %></title>
<SCRIPT>
function on_submit()
{
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">WDS AP</p>
 <p class="intro_content"> <% multilang("825" "LANG_THIS_TABLE_SHOWS_THE_MAC_ADDRESS_TRANSMISSION_RECEPTION_PACKET_COUNTERS_AND_STATE_INFORMATION_FOR_EACH_CONFIGURED_WDS_AP"); %></p>
</div>
<form action=/boaform/formWirelessTbl method=POST name="formWirelessTbl">
<div class="data_vertical data_common_notitle">
 <div class="data_common ">
  <table>
   <tr>
    <th><% multilang("92" "LANG_MAC_ADDRESS"); %></th>
    <th width="15%" class="table_item"><% multilang("165" "LANG_TX_PACKETS"); %></th>
    <th width="15%" class="table_item"><% multilang("826" "LANG_TX_ERRORS"); %></th>
    <th width="15%" class="table_item"><% multilang("166" "LANG_RX_PACKETS"); %></th>
    <th width="25%" class="table_item"><% multilang("167" "LANG_TX_RATE_MBPS"); %></th>
   </tr>
   <% wdsList(); %>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type="hidden" value="/wlwdstbl.asp" name="submit-url">
 <input class="link_bg" type="submit" value="<% multilang("441" "LANG_REFRESH"); %>" onClick="return on_submit()">&nbsp;&nbsp;
 <input class="link_bg" type="button" value="<% multilang("742" "LANG_CLOSE"); %>" name="close" onClick="javascript: window.close();">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
