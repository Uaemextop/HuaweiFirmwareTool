<%SendWebHeadStr(); %>
<title>DHCPv6 <% multilang("383" "LANG_SETTINGS"); %></title>
<SCRIPT>
function openWindow(url, windowName)
{
 var wide = 900;
 var high = 600;
 if (document.all)
  var xMax = screen.width, yMax = screen.height;
 else if (document.layers)
  var xMax = window.outerWidth, yMax = window.outerHeight;
 else
  var xMax = 640, yMax = 480;
 var xOffset = (xMax - wide) / 2;
 var yOffset = (yMax - high) / 3;
 var settings =
     'width=' + wide + ',height=' + high + ',screenX=' + xOffset +
     ',screenY=' + yOffset + ',top=' + yOffset + ',left=' + xOffset +
     ', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';
 window.open(url, windowName, settings);
}
function showDhcpv6Svr()
{
 var html;
 if (document.dhcpd.dhcpdenable[0].checked == true)
  document.getElementById('displayDhcpSvr').innerHTML=
   '<div class="btn_ctl">'+
   '<input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
   '</div>';
 else if (document.dhcpd.dhcpdenable[1].checked == true)
  document.getElementById('displayDhcpSvr').innerHTML=
   '<div class="data_common data_common_notitle">'+
   '<table>'+
   '<tr><td colspan=2>'+
   '<% multilang("753" "LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_THE_UPPER_INTERFACE_SERVER_LINK_FOR_DHCPV6_RELAY"); %>'+
   '</td></tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("754" "LANG_UPPER_INTERFACE"); %>:</th>'+
   '<td>'+
   '<select name="upper_if">'+
   '<% if_wan_list("all2"); %>'+
   '</select>'+
   '</td>'+
   '</tr>'+
   '</table></div>'+
   '<div class="btn_ctl">'+
   '<input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
   '</div>';
 else if (document.dhcpd.dhcpdenable[2].checked == true) {
  html=
   '<div class="data_common data_common_notitle">'+
   '<table>'+
   '<tr><td colspan=2>'+
   '<% multilang("755" "LANG_ENABLE_THE_DHCPV6_SERVER_IF_YOU_ARE_USING_THIS_DEVICE_AS_A_DHCPV6_SERVER_THIS_PAGE_LISTS_THE_IP_ADDRESS_POOLS_AVAILABLE_TO_HOSTS_ON_YOUR_LAN_THE_DEVICE_DISTRIBUTES_NUMBERS_IN_THE_POOL_TO_HOSTS_ON_YOUR_NETWORK_AS_THEY_REQUEST_INTERNET_ACCESS"); %>'+
   '</td></tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("361" "LANG_IP_POOL_RANGE"); %>:</th>';
  html+=
   '<td width="70%"><input type="text" name="dhcpRangeStart" size=25 maxlength=39 value="<% getInfo("dhcpv6s_range_start"); %>">'+
   '<font face="Arial" size="5">-</font><input type="text" name="dhcpRangeEnd" size=25 maxlength=39 value="<% getInfo("dhcpv6s_range_end"); %>">&nbsp;';
  html+= '<input type="button" value="<% multilang("363" "LANG_SHOW_CLIENT"); %>" name="dhcpClientTblv6" onClick="openWindow(\'/dhcptblv6.asp\', \'\')" >'+
   '</td>'+
   '</tr>';
  html += '<tr>'+
   '<th width="30%"><% multilang("472" "LANG_PREFIX_LENGTH"); %>:</th>'+
   '<td width="70%">'+
   '<input type="text" name="prefix_len" size=10 maxlength=3 value="<% getInfo("dhcpv6s_prefix_length"); %>">'+
   '</td>'+
   '</tr>';
  html += '<tr>'+
   '<th width="30%"><% multilang("756" "LANG_VALID_LIFETIME"); %>:</th>'+
   '<td width="70%">'+
   '<input type="text" name="Dltime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_default_LTime"); %>"><b> <% multilang("365" "LANG_SECONDS"); %></b>'+
   '</td>'+
   '</tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("757" "LANG_PREFERRED_LIFETIME"); %>:</th>'+
   '<td width="70%">'+
   '<input type="text" name="PFtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_preferred_LTime"); %>"><b> <% multilang("365" "LANG_SECONDS"); %></b>'+
   '</td>'+
   '</tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("758" "LANG_RENEW_TIME"); %>:</th>'+
   '<td width="70%">'+
   '<input type="text" name="RNtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_renew_time"); %>"><b> <% multilang("365" "LANG_SECONDS"); %></b>'+
   '</td>'+
   '</tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("759" "LANG_REBIND_TIME"); %>:</th>'+
   '<td width="70%">'+
   '<input type="text" name="RBtime" size=10 maxlength=9 value="<% getInfo("dhcpv6s_rebind_time"); %>"><b> <% multilang("365" "LANG_SECONDS"); %></b>'+
   '</td>'+
   '</tr>'+
   '<tr>'+
   '<th width="30%"><% multilang("760" "LANG_CLIENT"); %> DUID:</th>'+
   '<td width="70%">'+
   '<input type="text" name="clientID" size=42 maxlength=41 value="<% getInfo("dhcpv6s_clientID"); %>">'+
   '</td>'+
   '</tr>'+
   '</table></div>'+
   '<div class="btn_ctl">'+
   '<input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveChanges(this)" class="link_bg">&nbsp;&nbsp;'+
   '</div>'+
   '<div class="data_common data_common_notitle">'+
   '<table>'+
   '<tr>'+
   '<th width="30%"><% multilang("427" "LANG_DOMAIN"); %>:</th>'+
   '<td><input type="text" name="domainStr" size="15" maxlength="50">&nbsp;&nbsp;</td>'+
   '<td><input type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addDomain" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>'+
   '</tr>'+
   '</table>'+
   '</div>'+
   '<div class="column">'+
   '<div class="column_title">'+
   '<div class="column_title_left"></div>'+
   '<p><% multilang("761" "LANG_DOMAIN_SEARCH_TABLE"); %></p>'+
   '<div class="column_title_right"></div>'+
   '</div>'+
   '<div class="data_common data_vertical">'+
   '<table>'+
   <% showDhcpv6SDOMAINTable(); %>
   '</table>'+
   '</div></div>'+
   '<div class="btn_ctl">'+
   '<input type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="delDomain" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;'+
   '<input type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="delAllDomain" class="link_bg" onClick="return on_submit(this)">&nbsp;&nbsp;&nbsp;'+
   '</div>'+
   '<div class="data_common data_common_notitle">'+
   '<table>'+
   '<tr>'+
   '<th width="30%"><% multilang("762" "LANG_NAME_SERVER"); %> IP:</th>'+
   '<td><input type="text" name="nameServerIP" size="15" maxlength="40">&nbsp;&nbsp;</td>'+
   '<td><input type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addNameServer" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>'+
   '</tr>'+
   '</table>'+
   '</div>'+
   '<div class="column">'+
   '<div class="column_title">'+
   '<div class="column_title_left"></div>'+
   '<p><% multilang("763" "LANG_NAME_SERVER_TABLE"); %></p>'+
   '<div class="column_title_right"></div>'+
   '</div>'+
   '<div class="data_common data_vertical">'+
   '<table>'+
   <% showDhcpv6SNameServerTable(); %>
   '</table>'+
   '</div>'+
   '<div class="btn_ctl">'+
   '<input class="link_bg" type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="delNameServer" <% multilang("763" "LANG_NAME_SERVER_TABLE"); %> onClick="return on_submit(this)">&nbsp;&nbsp;'+
   '<input class="link_bg" type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="delAllNameServer" <% multilang("763" "LANG_NAME_SERVER_TABLE"); %> onClick="return on_submit(this)">&nbsp;&nbsp;&nbsp;'+
   '</div>';
  document.getElementById('displayDhcpSvr').innerHTML=html;
 }
 else if (document.dhcpd.dhcpdenable[3].checked == true)
  document.getElementById('displayDhcpSvr').innerHTML=
   '<div class="data_common data_common_notitle">'+
   '<table>'+
   '<tr><td>'+
   '<% multilang("764" "LANG_AUTO_CONFIG_BY_PREFIX_DELEGATION_FOR_DHCPV6_SERVER"); %>'+
   '</td></tr>'+
   '</table></div>'+
            '<table border=0 width="500" cellspacing=4 cellpadding=0>'+
            '<tr>'+
            '<td width="30%"><font size=2><b><% multilang("361" "LANG_IP_POOL_RANGE"); %><% multilang("362" "LANG_LAST_64_BIT_OF_IPV6_ADDR"); %>:</b></td>'+
            '<td width="70%"><input type="text" name="dhcpRangeStart" size=40 maxlength=39 value="<% getInfo("dhcpv6s_min_address"); %>">'+
            '<font face="Arial" size="5">- <input type="text" name="dhcpRangeEnd" size=40 maxlength=39 value="<% getInfo("dhcpv6s_max_address"); %>">&nbsp;'+
            '</td>'+
            '</tr>'+
            '</table>'+
   '<div class="btn_ctl">'+
   '<input type="button" value="<% multilang("363" "LANG_SHOW_CLIENT"); %>" name="dhcpClientTblv6" class="link_bg" onClick="openWindow(\'/dhcptblv6.asp\', \'\')" >&nbsp;&nbsp;'+
   '<input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" class="link_bg" onClick="return on_submit(this)"></tr>'+
   '</div>';
}
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function checkDigitRange_leaseTime(str, min)
{
  d = parseInt(str, 10);
  if ( d < min || d == 0)
       return false;
  return true;
}
function validateKey_leasetime(str)
{
   for (var i=0; i<str.length; i++) {
    if ( (str.charAt(i) >= '0' && str.charAt(i) <= '9') ||
      (str.charAt(i) == '-' ) )
   continue;
 return 0;
  }
  return 1;
}
function saveChanges(obj)
{
 if (document.dhcpd.dhcpRangeStart.value =="") {
  alert(document.dhcpd.dhcpRangeStart.value + "is invalid start address, should fill last 64 bit of IPv6 address. Format: \"xxxx:xxxx:xxxx:xxxx\" x should be Hex, Example:\"1:1:a:a\"");
  document.dhcpd.dhcpRangeStart.value = document.dhcpd.dhcpRangeStart.defaultValue;
  document.dhcpd.dhcpRangeStart.focus();
  return false;
 } else {
  if (! isUnicastIpv6AddressForDHCPv6( '0::'+document.dhcpd.dhcpRangeStart.value) ){
   alert(document.dhcpd.dhcpRangeStart.value + "is invalid start address, should fill last 64 bit of IPv6 address. Format: \"xxxx:xxxx:xxxx:xxxx\" x should be Hex, Example:\"1:1:a:a\"");
   document.dhcpd.dhcpRangeStart.focus();
   return false;
  }
 }
 if (document.dhcpd.dhcpRangeEnd.value =="") {
  alert(document.dhcpd.dhcpRangeEnd.value + "is invalid end address, should fill last 64 bit of IPv6 address. Format: \"xxxx:xxxx:xxxx:xxxx\" x should be Hex, Example:\"1:1:a:a\"");
  document.dhcpd.dhcpRangeEnd.value = document.dhcpd.dhcpRangeEnd.defaultValue;
  document.dhcpd.dhcpRangeEnd.focus();
  return false;
 } else {
  if (! isUnicastIpv6AddressForDHCPv6( '0::'+document.dhcpd.dhcpRangeEnd.value) ){
   alert(document.dhcpd.dhcpRangeEnd.value + "is invalid end address, should fill last 64 bit of IPv6 address. Format: \"xxxx:xxxx:xxxx:xxxx\" x should be Hex, Example:\"1:1:a:a\"");
   document.dhcpd.dhcpRangeEnd.focus();
   return false;
  }
 }
 obj.isclick = 1;
 postTableEncrypt(document.dhcpd.postSecurityFlag, document.dhcpd);
 return true;
}
function enabledhcpd()
{
 document.dhcpd.dhcpdenable[2].checked = true;
 showDhcpv6Svr();
}
function disabledhcpd()
{
 document.dhcpd.dhcpdenable[0].checked = true;
 showDhcpv6Svr();
}
function enabledhcprelay()
{
 document.dhcpd.dhcpdenable[1].checked = true;
 showDhcpv6Svr();
}
function autodhcpd()
{
 document.dhcpd.dhcpdenable[3].checked = true;
 showDhcpv6Svr();
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">DHCPv6 <% multilang("383" "LANG_SETTINGS"); %></p>
 <p class="intro_content"><% multilang("765" "LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_DHCPV6_SERVER_AND_DHCPV6_RELAY"); %></p>
</div>
<form action=/boaform/formDhcpv6Server method=POST name="dhcpd">
 <div class="data_common data_common_notitle">
  <table border=0 width="500" cellspacing=4 cellpadding=0>
   <tr>
    <th width="20%">DHCPv6 <% multilang("143" "LANG_MODE"); %>: </th>
    <td>
     <% checkWrite("dhcpV6Mode"); %>
    </td>
   </tr>
  </table>
 </div>
 <div ID="displayDhcpSvr"></div>
 <input type="hidden" value="/dhcpdv6.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
 <script>
  <% initPage("dhcpv6-mode"); %>
  showDhcpv6Svr();
 </script>
</form>
<br><br>
</body>
</html>
