<% SendWebHeadStr();%>
<title>Tracert <% multilang("44" "LANG_DIAGNOSTICS"); %></title>
<script>
function on_Apply()
{
 if(document.getElementById('traceAddr').value == "")
 {
  alert("Should input a domain or ip address!");
  document.getElementById('traceAddr').focus();
  return false;
 }
 return true;
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">Traceroute <% multilang("44" "LANG_DIAGNOSTICS"); %></p>
 <p class="intro_content"><% multilang("498" "LANG_PAGE_DESC_TRACERT_DIAGNOSTIC"); %></p>
</div>
<form id="form" action=/boaform/formTracert method=POST>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("96" "LANG_PROTOCOL"); %>:</th>
   <td width="70%">
    <select name="proto">
     <option value="0">ICMP</option>
     <option value="1">UDP</option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("500" "LANG_HOST_ADDRESS"); %>:</th>
   <td width="70%"><input type="text" id="traceAddr" name="traceAddr" size="30" maxlength="50"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3008" "LANG_NUMBER_OF_TRIES"); %>:</th>
   <td width="70%"><input type="text" id="trys" name="trys" size="5" maxlength="5" value="3"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3009" "LANG_TIME_OUT"); %>:</th>
   <td width="70%"><input type="text" id="timeout" name="timeout" size="10" maxlength="10" value="5">s</td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3010" "LANG_DATA_SIZE"); %>:</th>
   <td width="70%"><input type="text" id="datasize" name="datasize" size="10" maxlength="10" value="56">Bytes</td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3011" "LANG_DSCP"); %>:</th>
   <td width="70%"><input type="text" id="dscp" name="dscp" size="10" maxlength="10" value="0"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3012" "LANG_MAX_HOP_COUNT"); %>:</th>
   <td width="70%"><input type="text" id="maxhop" name="maxhop" size="10" maxlength="10" value="30"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("432" "LANG_WAN_INTERFACE"); %>: </th>
   <td width="70%"><select name="wanif"><% if_wan_list("rt-any-vpn"); %></select></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value=" <% multilang("501" "LANG_GO"); %>" name="go" onClick="return on_Apply()">
 <input type="hidden" value="/tracert.asp" name="submit-url">
</div>
</form>
<br>
<br>
</body>
</html>
