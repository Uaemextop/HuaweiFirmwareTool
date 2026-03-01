<%SendWebHeadStr(); %>
<title><% multilang("3021" "LANG_LOOP_DETECTION"); %></title>
<SCRIPT>
<% initLBDPage(); %>
function on_init()
{
 if(lbd_enable)
  document.lbd.enable.checked = true;
 document.lbd.exist_period.value = lbd_exist_period;
 document.lbd.cancel_period.value = lbd_cancel_period;
 document.lbd.ether_type.value = lbd_ether_type.toString(16).toUpperCase();
 document.lbd.vlans.value = lbd_vlans;
 var table = document.getElementById("port_status");
 for(var i = 0 ; i < lbd_port_status.length ; i++)
 {
  var cell;
  var row = table.insertRow(-1);
  cell = row.insertCell(0);
  cell.innerHTML = "LAN" + (i+1);
  cell = row.insertCell(1);
  switch(lbd_port_status[i])
  {
  case 0:
   cell.innerHTML = "<% multilang("3022" "LANG_LOOP_DETECTION_STATUS_FALSE"); %>";
   break;
  case 1:
   cell.innerHTML = "<% multilang("3023" "LANG_LOOP_DETECTION_STATUS_TRUE_AND_DISABLE_PORT"); %>";
   break;
  case 2:
   cell.innerHTML = "<% multilang("3024" "LANG_LOOP_DETECTION_STATUS_TRUE_BUT_NOT_DISABLED_PORT"); %>";
   break;
  }
 }
 update_gui();
}
function disable_by_class(str_class, disable)
{
 var elements = document.getElementsByClassName(str_class);
 for (var i = 0 ; i < elements.length ; i++)
  elements[i].disabled = disable;
}
function update_gui()
{
 with(document.lbd)
 {
  if(enable.checked == true)
   disable_by_class("lbd", false);
  else
   disable_by_class("lbd", true);
 }
}
function on_submit()
{
 with(document.lbd)
 {
  if(enable.checked == false)
  {
   document.forms[0].save.isclick = 1;
   postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
   return true;
  }
  if(!sji_checkdigitrange(exist_period.value, 1, 60))
  {
   alert("<% multilang("3025" "LANG_LOOP_DETECTION_INTERVAL_TIME_SHOULD_BE_1_TO_60_SEC"); %>!");
   exist_period.focus();
   return false;
  }
  if(!sji_checkdigitrange(cancel_period.value, 10, 1800))
  {
   alert("<% multilang("3026" "LANG_LOOP_DETECTION_RECOVERY_INTERVAL_TIME_SHOULD_BE_10_TO_1800_SEC"); %>!");
   cancel_period.focus();
   return false;
  }
  if(!sji_checkhex(ether_type.value, 1, 4))
  {
   alert("<% multilang("3027" "LANG_LOOP_DETECTION_ETHER_TYPE_SHOULD_BE_IN_HEX_NUMBER"); %>!");
   ether_type.focus();
   return false;
  }
  if(vlans.value.length <= 0)
  {
   alert("<% multilang("3028" "LANG_LOOP_DETECTION_MUST_ASSIGN_VLAN_NUMBER"); %>!");
   vlans.focus();
   return false;
  }
 }
 document.forms[0].save.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function on_refresh(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body onLoad="on_init();">
<div class="intro_main ">
 <p class="intro_title"><% multilang("3021" "LANG_LOOP_DETECTION"); %></p>
 <p class="intro_content"><% multilang("3036" "LANG_THIS_PAGE_IS_USED_TO_CONFIGURE_LOOP_DETECTION_PARAMETERS_HERE_YOU_CAN_CHANGE_THE_SETTINGS_OR_VIEW_LOOP_DETECTION_STATUS"); %></p>
</div>
<form action=/boaform/formLBD method=POST name="lbd">
<div class="column clearfix">
 <div class="column_title">
  <div class="column_title_left"></div>
  <p><% multilang("3021" "LANG_LOOP_DETECTION"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
  <div class="column_title_right"></div>
 </div>
</div>
<div class="data_common">
<table>
  <tr>
      <th width="30%"><% multilang("3029" "LANG_LOOP_DETECTION_ENABLE"); %>:</th>
      <td width="70%"><input type="checkbox" name="enable" value="1" onClick="update_gui();"></td>
  </tr>
  <tr>
      <th width="30%"><% multilang("3030" "LANG_LOOP_DETECTION_INTERVAL"); %>:</th>
      <td width="70%"><input type="text" class="lbd" name="exist_period" size="15" maxlength="5"> (1~60)<% multilang("365" "LANG_SECONDS"); %></td>
  </tr>
  <tr>
      <th width="30%"><% multilang("3031" "LANG_LOOP_DETECTION_RECOVERY_INTERVAL"); %>:</th>
      <td width="70%"><input type="text" class="lbd" name="cancel_period" size="15" maxlength="15"> (10 ~ 1800)<% multilang("365" "LANG_SECONDS"); %></td>
  </tr>
  <tr>
      <th width="30%"><% multilang("3032" "LANG_LOOP_DETECTION_ETHER_TYPE"); %>:</th>
      <td width="70%">0x<input type="text" class="lbd" name="ether_type" size="13" maxlength="4"></td>
  </tr>
  <tr>
      <th width="30%"><% multilang("135" "LANG_VLAN_ID"); %>:</th>
      <td width="70%"><input type="text" class="lbd" name="vlans" size="30" maxlength="300"></td>
  </tr>
  <tr><th></th><td width="70%"><% multilang("3033" "LANG_LOOP_DETECTION_SEPERATE_BY_COMMA_0_REPRESENT_UNTAGGED_EX_0_45_46"); %></td></tr>
</table>
</div>
<div class="column clearfix">
 <div class="column_title">
  <div class="column_title_left"></div>
  <p><% multilang("3021" "LANG_LOOP_DETECTION"); %><% multilang("3035" "LANG_LOOP_DETECTION_STATUS"); %></p>
  <div class="column_title_right"></div>
 </div>
</div>
<div class="data_common data_vertical">
 <table id="port_status">
  <tr>
   <th align=center><% multilang("3034" "LANG_LOOP_DETECTION_LAN_PORT"); %></th>
   <th align=center><% multilang("3035" "LANG_LOOP_DETECTION_STATUS"); %></th>
  </tr>
 </table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return on_submit()">&nbsp;&nbsp;
      <input class="link_bg" type="submit" value="<% multilang("441" "LANG_REFRESH"); %>" name="refresh" onClick="return on_refresh(this)">&nbsp;&nbsp;
      <input type="hidden" value="/lbd.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
