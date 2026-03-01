<% SendWebHeadStr();%>
<title><% multilang("267" "LANG_WLAN_EASY_MESH_INTERFACE_SETUP"); %></title>
<style>
.on {display:on}
.off {display:none}
</style>
<SCRIPT>
var role=<% getInfo("multi_ap_controller"); %>;
function wpsTrigger(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
    return true;
}
function loadInfo()
{
 if (role == 0) {
  document.getElementById("role_disabled").checked = true;
 } else if (role == 1) {
  document.getElementById("role_controller").checked = true;
  document.getElementById("wsc_trigger").innerHTML = '<th width="30%">'+'<% multilang("270" "LANG_WLAN_WPS_TRIGGER"); %>'+':</th><td width="70%"><input type="submit" value="'+'<%multilang("248" "LANG_START_PBC"); %>'+'" class="link_bg" name="start_wsc" onClick="return wpsTrigger(this)"></td>';
 }
 if (role == 0) {
  document.getElementById("role_prev").value = "disabled";
 } else if (role == 1) {
  document.getElementById("role_prev").value = "controller";
 }
}
function resetClick()
{
 location.reload(true);
}
function saveChanges(obj)
{
 if (!document.getElementById("role_disabled").checked) {
  if ("" == document.getElementById("device_name_text").value) {
   alert("<% multilang("273" "LANG_WLAN_EASY_MESH_DEVICE_NAME_CANNOT_BE_EMPTY"); %>");
   return false;
  }
 }
 var dot11kvDisabled = <% checkWrite("is_dot11kv_disabled"); %>;
 if (dot11kvDisabled && (!document.getElementById("role_disabled").checked)) {
  if(!confirm("<% multilang("275" "LANG_WLAN_EASY_MESH_11KV_ENABLE_WARNING_MESSAGE"); %>")){
   return false;
  }
  document.getElementById("needEnable11kv").value = "1";
 }
 var securitySettingWrong = <% checkWrite("is_security_setting_wrong"); %>;
 if (securitySettingWrong && (role == 1)) {
  alert("<% multilang("276" "LANG_WLAN_EASY_MESH_SECURTITY_WRONG_MESSAGE"); %>");
  return false;
 }
 if (<% checkWrite("needPopupBackhaul"); %> && (role == 1)) {
  if(!confirm("<% multilang("277" "LANG_WLAN_EASY_MESH_ALERT_VAP1_AUTO_MANAGED_MESSAGE"); %>")){
   return false;
  }
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
    return true;
}
function isControllerOnChange(){
 if (document.getElementById("role_controller").checked == true) {
  role = 1;
 } else {
  role = 0;
 }
}
</SCRIPT>
</head>
<body onload="loadInfo();">
<div class="intro_main ">
 <p class="intro_title"><% multilang("267" "LANG_WLAN_EASY_MESH_INTERFACE_SETUP"); %></p>
 <p class="intro_content"><% multilang("278" "LANG_WLAN_EASY_MESH_DESC"); %></p>
</div>
<form action=/boaform/formMultiAP method=POST name="MultiAP">
<div class="data_common data_common_notitle">
<table>
  <!-- <tr>
 <td width="100%" colspan=2><font size=2><b>
  <input type="checkbox" name="" value="ON" ONCLICK="">&nbsp;&nbsp;Disable EasyMesh</b>
 </td>
 </tr> -->
 <tr id="device_name">
  <th width="30%"><% multilang("100" "LANG_DEVICE_NAME"); %>:</th>
  <td width="70%">
   <input type="text" id="device_name_text" name="device_name_text" value="<% getInfo("map_device_name"); %>">
  </td>
 </tr>
 <tr id="is_controller">
  <th width="30%"><% multilang("269" "LANG_ROLE"); %>:</th>
  <td width="70%">
  <input type="radio" id="role_controller" name="role" value="controller" onclick="isControllerOnChange()"><% multilang("271" "LANG_CONTROLLER"); %>&nbsp;&nbsp;
<!-- <input type="radio" id="role_agent" name="role" value="agent" onclick="isControllerOnChange()"><% multilang("272" "LANG_AGENT"); %>&nbsp;&nbsp; -->
  <input type="radio" id="role_disabled" name="role" value="disabled" onclick="isControllerOnChange()"><% multilang("186" "LANG_DISABLED"); %></td>
 </tr>
 <tr id="wsc_trigger">
 </tr>
   <!-- <tr>
  <td width="100%" colspan=2><font size=2><b>Network Topology:</b></td>
  <td width="100%" colspan=2><font size=2><b>Neighbor Table:</b></td>
 </tr> -->
  </table>
 <!-- <table width="400" border="0&quot;">
   <tbody><tr>
     <td width="100%" colspan="2" class="tbl_title">Parent Node</td>
   </tr>
   <tr bgcolor="#DDDDDD">
     <td width="40%"><font size="2"><b>Agent1</b></font></td>
     <td width="60%"><font size="2">1a2b3c4d5e7f</font></td>
   </tr>
   <tr>
   <td width="100%" colspan="2" class="tbl_title">Child Node</td>
   </tr>
   <tr bgcolor="#DDDDDD">
   <td width="40%"><font size="2"><b>Agent3</b></font></td>
   <td width="60%"><font size="2">2a2b3c4d5e7f</font></td>
   </tr>
   <tr bgcolor="#EEEEEE">
   <td width="40%"><font size="2"><b>Agent4</b></font></td>
   <td width="60%"><font size="2">3a2b3c4d5e7f</font></td>
   </tr>
   <tr bgcolor="#DDDDDD">
   <td width="40%"><font size="2"><b>Agent5</b></font></td>
   <td width="60%"><font size="2">3a2b3c4d5e7f
   </font></td>
   </tr>
    </tbody></table> -->
 <table style="display:none;" id="staticIpTable" border="0" width=640>
  <% dhcpRsvdIp_List();%>
 </table>
</div>
<div class="btn_ctl">
      <input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" class="link_bg" name="save_apply" onClick="return saveChanges(this)">&nbsp;&nbsp;
      <input type="reset" value="<% multilang("229" "LANG_RESET"); %>" class="link_bg" name="reset" onClick="resetClick()">
<!-- <div id="syntaxplugin" class="syntaxplugin" style="border: 1px dashed #bbb; border-radius: 5px !important; overflow: auto; max-height: 30em;">
  <ul class="alternate" type="square">
    <li> Controller - 1a2b3c4d5e6f - <input type="button" value="Show Details" onClick="abc()">
    <ul class="alternate" type="square">
     <li>AgentLivingRoom : 1a2b3c4d5e7f</li>
     <li>AgentBedroom1 : 1a2b3c4d5e8f
     <ul class="alternate" type="square">
      <li>AgentBedroom2 : 2a2b3c4d5e6f
      <ul class="alternate" type="square">
       <li>Agent4 : 3a2b3c4d5e6f</li>
       <li>Agent5 : 4a2b3c4d5e6f</li>
       <li>Agent6 : 5a2b3c4d5e6f</li>
      </ul>
      </li>
      <li>Agent7 : 1a3b3c4d5e6f
      <ul class="alternate" type="square">
       <li>Agent8 : 7a2b3c4d5e6f</li>
       <li>Agent9 : 8a2b3c4d5e6f</li>
       <li>Agent10 : 9a2b3c4d5e6f</li>
      </ul>
      </li>
      <li>Agent11 : 0a2b3c4d5e6f
      <ul class="alternate" type="square">
       <li>Agent12 : 4a2b3c3d5e6f</li>
       <li>Agent13 : 3a2b3c8d5e6f</li>
       <li>Agent14 : 2a2b3c1d5e6f</li>
       <li>Agent15 : 1a2b3c4d5e2f</li>
      </ul>
      </li>
     </ul>
     </li>
     <li>Agent16 : 2a2b3c4d5e6f</li>
     <li>Agent17 : 5a2b3c4d5e6f</li>
    </ul>
    </li>
   </ul>
</div> -->
   <input type="hidden" value="/multi_ap_setting_general.asp" name="submit-url">
   <input type="hidden" value="0" name="needEnable11kv" id="needEnable11kv">
   <input type="hidden" value="<% getIndex("needPopupBackhaul"); %>" name="needPopupBackhaul">
   <input type="hidden" value="" name="role_prev" id="role_prev">
   <input type="hidden" name="postSecurityFlag" value="">
 </div>
 </form>
</body>
</html>
