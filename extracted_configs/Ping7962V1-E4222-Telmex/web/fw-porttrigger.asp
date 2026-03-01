<%SendWebHeadStr(); %>
<title><% multilang("25" "LANG_PORT_TRIGGERING"); %><% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function addClick(obj)
{
 if (document.formPortTriggerAdd.portTriggercap[0].checked){
  obj.isclick = 1;
  postTableEncrypt(document.formPortTriggerAdd.postSecurityFlag, document.formPortTriggerAdd);
  return true;
 }
 if (document.formPortTriggerAdd.localFromPort.value=="" && document.formPortTriggerAdd.localToPort.value=="" && document.formPortTriggerAdd.comment.value=="" ){
     alert('<% multilang("2248" "LANG_LOCAL_SETTINGS_CANNOT_BE_EMPTY"); %>');
   return false;
 }
    console.debug("localFromPort "+document.formPortTriggerAdd.localFromPort.value);
 if (document.formPortTriggerAdd.localFromPort.value!="") {
  if ( validateKey( document.formPortTriggerAdd.localFromPort.value ) == 0 ) {
   alert('<% multilang("2251" "LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9"); %>');
   document.formPortTriggerAdd.localFromPort.focus();
   return false;
  }
  d2 = getDigit(document.formPortTriggerAdd.localFromPort.value, 1);
  if (d2 > 65535 || d2 < 1) {
   alert('<% multilang("2252" "LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535"); %>');
   document.formPortTriggerAdd.localFromPort.focus();
   return false;
  }
 }
    console.debug("remoteFromPort "+document.formPortTriggerAdd.remoteFromPort.value);
 if (document.formPortTriggerAdd.remoteFromPort.value!="") {
  if ( validateKey( document.formPortTriggerAdd.remoteFromPort.value ) == 0 ) {
   alert('<% multilang("2251" "LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9"); %>');
   document.formPortTriggerAdd.remoteFromPort.focus();
   return false;
  }
  d2 = getDigit(document.formPortTriggerAdd.remoteFromPort.value, 1);
  if (d2 > 65535 || d2 < 1) {
   alert('<% multilang("2252" "LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535"); %>');
   document.formPortTriggerAdd.remoteFromPort.focus();
   return false;
  }
 }
 if (document.formPortTriggerAdd.localToPort.value!="") {
  if ( validateKey( document.formPortTriggerAdd.localToPort.value ) == 0 ) {
   alert('<% multilang("2251" "LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9"); %>');
   document.formPortTriggerAdd.localToPort.focus();
   return false;
  }
  d2 = getDigit(document.formPortTriggerAdd.localToPort.value, 1);
  if (d2 > 65535 || d2 < 1) {
   alert('<% multilang("2252" "LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535"); %>');
   document.formPortTriggerAdd.localToPort.focus();
   return false;
  }
 }
 if (document.formPortTriggerAdd.remoteToPort.value!="") {
  if ( validateKey( document.formPortTriggerAdd.remoteToPort.value ) == 0 ) {
   alert('<% multilang("2251" "LANG_INVALID_PORT_NUMBER_IT_SHOULD_BE_THE_DECIMAL_NUMBER_0_9"); %>');
   document.formPortTriggerAdd.remoteToPort.focus();
   return false;
  }
  d2 = getDigit(document.formPortTriggerAdd.remoteToPort.value, 1);
  if (d2 > 65535 || d2 < 1) {
   alert('<% multilang("2252" "LANG_INVALID_PORT_NUMBER_YOU_SHOULD_SET_A_VALUE_BETWEEN_1_65535"); %>');
   document.formPortTriggerAdd.remoteToPort.focus();
   return false;
  }
 }
   obj.isclick = 1;
 postTableEncrypt(document.formPortTriggerAdd.postSecurityFlag, document.formPortTriggerAdd);
 return true;
}
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.formPortTriggerAdd.postSecurityFlag, document.formPortTriggerAdd);
 return true;
}
function disableDelButton()
{
  if (verifyBrowser() != "ns") {
 disableButton(document.formPortTriggerDel.deleteSelPortTrigger);
 disableButton(document.formPortTriggerDel.deleteSelPortTrigger);
  }
}
function deleteClick(obj)
{
 if ( !confirm('<% multilang("1753" "LANG_CONFIRM_DELETE_ONE_ENTRY"); %>') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.formPortTriggerDel.postSecurityFlag, document.formPortTriggerDel);
  return true;
 }
}
function deleteAllClick(obj)
{
 if ( !confirm('Do you really want to delete the all entries?') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.formPortTriggerDel.postSecurityFlag, document.formPortTriggerDel);
  return true;
 }
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("25" "LANG_PORT_TRIGGERING"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"><% multilang("3062" "LANG_ENTRIES_IN_THIS_TABLE_ARE_USED_TO_OPEN_A_PORT_AUTOMATICALLY_FOR_INCOMING_TRAFFIC_AFTER_A_PORT_HAS_BEEN_ACCESSED_BY_OUTGOING_TRAFFIC"); %></p>
</div>
<form action=/boaform/formPortTrigger method=POST name="formPortTriggerAdd">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("25" "LANG_PORT_TRIGGERING"); %>:</th>
   <td width="30%">
    <input type="radio" value="0" name="portTriggercap" <% checkWrite("portTrigger-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
    <input type="radio" value="1" name="portTriggercap" <% checkWrite("portTrigger-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>
   </td>
  <td width="40%"><input class="inner_btn" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="apply" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle">
<table style ="table-layout:fixed; overflow:hidden;">
    <tr>
  <th width="25%">
   <% multilang("406" "LANG_COMMENT"); %>
  </th>
  <th width="10%">
   <% multilang("3063" "LANG_TRIGGER_START_PORT"); %>
  </th>
  <th width="10%">
   <% multilang("3064" "LANG_TRIGGER_END_PORT"); %>
  </th>
  <th width="15%">
   <% multilang("96" "LANG_PROTOCOL"); %>
  </th>
   <th width="10%">
   <% multilang("3065" "LANG_INCOMING_START_PORT"); %>
  </th>
   <th width="10%">
   <% multilang("3066" "LANG_INCOMING_END_PORT"); %>
  </th>
   <th>
   <% multilang("70" "LANG_INTERFACE"); %>
  </th>
    </tr>
 <tr>
  <td><input type="text" name="comment" size="15" maxlength="15"> </td>
  <td><input type="text" name="remoteFromPort" style="width:50px;" size="5" maxlength="5"></td>
  <td><input type="text" name="remoteToPort" style="width:50px;" size="5" maxlength="5"></td>
  <td>
   <select name="protocol">
    <option select value=4><% multilang("405" "LANG_BOTH"); %></option>
    <option value=1>TCP</option>
    <option value=2>UDP</option>
   </select><br>
  </td>
  <td><input type="text" name="localFromPort" size="5" style="width:50px;" maxlength="5"></td>
  <td><input type="text" name="localToPort" size="5" style="width:50px;" maxlength="5"></td>
  <td>
   <select name="interface">
    <% if_wan_list("rt"); %>
   </select>
  </td>
 </tr>
</table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addPortTrigger" onClick="return addClick(this)">
 <input type="hidden" value="/fw-porttrigger.asp" name="submit-url">
</div>
<input type="hidden" name="postSecurityFlag" value="">
</form>
<form action=/boaform/formPortTrigger method=POST name="formPortTriggerDel">
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
  <p> <% multilang("3067" "LANG_CURRENT_PORT_TRIGGERING_TABLE"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common data_vertical">
 <table>
  <% portTriggerList(); %>
 </table>
 </div>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="deleteSelPortTrigger" onClick="return deleteClick(this)">
 <input class="link_bg" type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="deleteAllPortTrigger" onClick="return deleteAllClick(this)">
</div>
 <script>
  <% checkWrite("portTriggerNum"); %>
 </script>
 <input type="hidden" value="/fw-porttrigger.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</form>
</body>
</html>
