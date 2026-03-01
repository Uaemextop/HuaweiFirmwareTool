<% SendWebHeadStr();%>
<title>Wan Mode <% multilang("245" "LANG_CONFIGURATION"); %></title>
<script type="text/javascript" src="base64_code.js"></script>
<script language="javascript">
<% checkWrite("wan_mode_table"); %>
function viewList()
{
 with (document.forms[0])
 {
  var wan_mode = wan_mode_select.value;
  if (wan_mode == 0)
  {
   lan_port_tr.style.display = "table-row";
  }
  else
  {
   lan_port_tr.style.display = "none";
  }
 }
 return true;
}
function wan_mode_change()
{
 with (document.forms[0])
 {
  viewList();
 }
 return true;
}
function saveClick()
{
 with (document.forms[0])
 {
  wan_mode_cfg.value = wan_mode_select.value;
  wan_lan_port_cfg.value = lan_port_select.value;
 }
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function formLoad()
{
 with (document.forms[0])
 {
  var e = document.getElementById("wan_mode_select");
  setSelect(e, current_pon_mode);
  if (current_pon_mode == "0")
  {
   e = document.getElementById("lan_port_select");
   setSelect(e, current_ethwan_lan_port);
  }
  viewList();
 }
 return true;
}
</SCRIPT>
</head>
<body onLoad="formLoad();">
<blockquote>
<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action="/boaform/formWANMode" method="POST" name="formWANMode">
<table border="0" cellpadding="0" cellspacing="0">
 <tr>
  <td width="200px">Select WAN Mode:</td>
  <td>
   <select name='wan_mode_select' id='wan_mode_select' onChange='wan_mode_change()'>
   <script language="javascript">
    var i = 0;
    for (i = 0; i < WANModeList.length; i++)
    {
     document.write("<option value=\"" + WANModeList[i] + "\">" + WANModeName[i] + "</option>");
    }
   </script>
   </select>
  </td>
 </tr>
 <tr id="lan_port_tr">
  <td width="200px">Select LAN port as WAN:</td>
  <td>
   <select name='lan_port_select' id='lan_port_select'>
   <script language="javascript">
    var i = 0;
    for (i = 0; i < sw_lan_port_num; i++)
    {
     document.write("<option value=\"" + i + "\">LAN " + (i + 1) + "</option>");
    }
   </script>
   </select>
  </td>
 </tr>
</table>
<table border="0" cellpadding="0" cellspacing="0">
 <tr>
  <td>
   <input type="submit" class="btnsaveup" value="Apply Changes" onClick="return saveClick()">
   <input type="hidden" name="wan_mode_cfg" value="0">
   <input type="hidden" name="wan_lan_port_cfg" value="0">
   <input type="hidden" value="/net_wan_mode.asp" name="submit-url">
   <input type="hidden" name="postSecurityFlag" value="">
  </td>
 </tr>
</table>
</form>
</DIV>
</blockquote>
</body>
</html>
