<%SendWebHeadStr(); %>
<title>IP/Port <% multilang("387" "LANG_FILTERING"); %></title>
<script>
function skip () { this.blur(); }
function protocolSelection()
{
 if ( document.formFilterAdd.protocol.selectedIndex == 2 )
 {
  document.formFilterAdd.sfromPort.disabled = true;
  document.formFilterAdd.stoPort.disabled = true;
  document.formFilterAdd.dfromPort.disabled = true;
  document.formFilterAdd.dtoPort.disabled = true;
 }
 else
 {
  document.formFilterAdd.sfromPort.disabled = false;
  document.formFilterAdd.stoPort.disabled = false;
  document.formFilterAdd.dfromPort.disabled = false;
  document.formFilterAdd.dtoPort.disabled = false;
 }
}
function addClick(obj)
{
 if (document.formFilterAdd.sip.value == "" && document.formFilterAdd.smask.value == ""
  && document.formFilterAdd.dip.value == "" && document.formFilterAdd.dmask.value == ""
  && document.formFilterAdd.sfromPort.value == "" && document.formFilterAdd.dfromPort.value == "") {
  alert('<% multilang("2229" "LANG_FILTER_RULES_CAN_NOT_BE_EMPTY"); %>');
  document.formFilterAdd.sip.focus();
  return false;
 }
 if (document.formFilterAdd.sip.value!="") {
  if (!checkHostIP(document.formFilterAdd.sip, 0))
   return false;
  if ( document.formFilterAdd.smask.value != "" ) {
   if (!checkNetmask(document.formFilterAdd.smask, 0))
    return false;
  }
 }
 if (document.formFilterAdd.dip.value!="") {
  if (!checkHostIP(document.formFilterAdd.dip, 0))
   return false;
  if ( document.formFilterAdd.dmask.value != "" ) {
   if (!checkNetmask(document.formFilterAdd.dmask, 0))
    return false;
  }
 }
 if ( document.formFilterAdd.sfromPort.value!="" ) {
  if ( validateKey( document.formFilterAdd.sfromPort.value ) == 0 ) {
   alert('<% multilang("2179" "LANG_INVALID_SOURCE_PORT"); %>');
   document.formFilterAdd.sfromPort.focus();
   return false;
  }
  d1 = getDigit(document.formFilterAdd.sfromPort.value, 1);
  if (d1 > 65535 || d1 < 1) {
   alert('<% multilang("2180" "LANG_INVALID_SOURCE_PORT_NUMBER"); %>');
   document.formFilterAdd.sfromPort.focus();
   return false;
  }
  if ( document.formFilterAdd.stoPort.value!="" ) {
   if ( validateKey( document.formFilterAdd.stoPort.value ) == 0 ) {
    alert('<% multilang("2179" "LANG_INVALID_SOURCE_PORT"); %>');
    document.formFilterAdd.stoPort.focus();
    return false;
   }
   d1 = getDigit(document.formFilterAdd.stoPort.value, 1);
   if (d1 > 65535 || d1 < 1) {
    alert('<% multilang("2180" "LANG_INVALID_SOURCE_PORT_NUMBER"); %>');
    document.formFilterAdd.stoPort.focus();
    return false;
   }
  }
 }
 if ( document.formFilterAdd.dfromPort.value!="" ) {
  if ( validateKey( document.formFilterAdd.dfromPort.value ) == 0 ) {
   alert('<% multilang("2181" "LANG_INVALID_DESTINATION_PORT"); %>');
   document.formFilterAdd.dfromPort.focus();
   return false;
  }
  d1 = getDigit(document.formFilterAdd.dfromPort.value, 1);
  if (d1 > 65535 || d1 < 1) {
   alert('<% multilang("2182" "LANG_INVALID_DESTINATION_PORT_NUMBER"); %>');
   document.formFilterAdd.dfromPort.focus();
   return false;
  }
  if ( document.formFilterAdd.dtoPort.value!="" ) {
   if ( validateKey( document.formFilterAdd.dtoPort.value ) == 0 ) {
    alert('<% multilang("2181" "LANG_INVALID_DESTINATION_PORT"); %>');
    document.formFilterAdd.dtoPort.focus();
    return false;
   }
   d1 = getDigit(document.formFilterAdd.dtoPort.value, 1);
   if (d1 > 65535 || d1 < 1) {
    alert('<% multilang("2182" "LANG_INVALID_DESTINATION_PORT_NUMBER"); %>');
    document.formFilterAdd.dtoPort.focus();
    return false;
   }
  }
 }
 obj.isclick = 1;
 postTableEncrypt(document.formFilterAdd.postSecurityFlag, document.formFilterAdd);
 return true;
}
function disableDelButton()
{
  if (verifyBrowser() != "ns") {
 disableButton(document.formFilterDel.deleteSelFilterIpPort);
 disableButton(document.formFilterDel.deleteAllFilterIpPort);
  }
}
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.formFilterDefault.postSecurityFlag, document.formFilterDefault);
 return true;
}
function deleteClick(obj)
{
 if ( !confirm('<% multilang("1753" "LANG_CONFIRM_DELETE_ONE_ENTRY"); %>') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
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
  postTableEncrypt(document.formFilterDel.postSecurityFlag, document.formFilterDel);
  return true;
 }
}
function dirChange()
{
 get_by_id("wanif_tr").style.display = "none";
 if (document.formFilterAdd.dir.value==1){
  get_by_id("wanif_tr").style.display = "";
 }
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">IP/Port <% multilang("387" "LANG_FILTERING"); %></p>
 <p class="intro_content"> <% multilang("388" "LANG_PAGE_DESC_DATA_PACKET_FILTER_TABLE"); %></p>
</div>
<form action=/boaform/formFilter method=POST name="formFilterDefault">
<div class="data_common data_common_notitle" <% checkWrite("rg_hidden_function"); %>>
 <table>
  <tr <% checkWrite("rg_hidden_function"); %>>
   <th width="30%"><% multilang("389" "LANG_OUTGOING_DEFAULT_ACTION"); %>:&nbsp;&nbsp;</th>
   <td width="70%"><input type="radio" name="outAct" value=0 <% checkWrite("ipf_out_act0"); %>><% multilang("390" "LANG_DENY"); %>&nbsp;&nbsp;
    <input type="radio" name="outAct" value=1 <% checkWrite("ipf_out_act1"); %>><% multilang("391" "LANG_ALLOW"); %>&nbsp;&nbsp;
   </td>
  </tr>
  <tr <% checkWrite("rg_hidden_function"); %>>
   <th width="30%"><% multilang("392" "LANG_INCOMING_DEFAULT_ACTION"); %>:&nbsp;&nbsp;</th>
   <td width="70%"><input type="radio" name="inAct" value=0 <% checkWrite("ipf_in_act0"); %>><% multilang("390" "LANG_DENY"); %>&nbsp;&nbsp;
    <input type="radio" name="inAct" value=1 <% checkWrite("ipf_in_act1"); %>><% multilang("391" "LANG_ALLOW"); %>&nbsp;&nbsp;
   </td>
  </tr>
 </table>
</div>
<div class="btn_ctl" <% checkWrite("rg_hidden_function"); %>>
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="setDefaultAction" onClick="return on_submit(this)">&nbsp;&nbsp;
 <input type="hidden" value="/fw-ipportfilter.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<form action=/boaform/formFilter method=POST name="formFilterAdd">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%">
    <% multilang("393" "LANG_DIRECTION"); %>:
   </th>
   <td width="70%">
    <select name=dir onChange="dirChange()">
     <option select value=0><% multilang("394" "LANG_OUTGOING"); %></option>
     <option value=1><% multilang("395" "LANG_INCOMING"); %></option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("96" "LANG_PROTOCOL"); %>:
   </th>
   <td width="70%">
    <select name="protocol" onChange="protocolSelection()">
     <option select value=1>TCP</option>
     <option value=2>UDP</option>
     <option value=3>ICMP</option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("396" "LANG_RULE_ACTION"); %>:
   </th>
   <td width="70%">
       <input type="radio" name="filterMode" value="Deny" checked>&nbsp;<% multilang("390" "LANG_DENY"); %>
       <input type="radio" name="filterMode" value="Allow">&nbsp;&nbsp;<% multilang("391" "LANG_ALLOW"); %>
      </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("397" "LANG_SOURCE"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:
   </th>
   <td width="70%">
    <input type="text" name="sip" size="10" maxlength="15">
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("90" "LANG_SUBNET_MASK"); %>:
   </th>
   <td width="70%">
    <input type="text" name="smask" size="10" maxlength="15">
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("220" "LANG_PORT"); %>:
   </th>
   <td width="70%">
    <input type="text" name="sfromPort" size="4" maxlength="5">-
     <input type="text" name="stoPort" size="4" maxlength="5">&nbsp;&nbsp;
    </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("398" "LANG_DESTINATION"); %> <% multilang("89" "LANG_IP_ADDRESS"); %>:
   </th>
   <td width="70%">
    <input type="text" name="dip" size="10" maxlength="15">
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("90" "LANG_SUBNET_MASK"); %>:
   </th>
   <td width="70%">
    <input type="text" name="dmask" size="10" maxlength="15">
   </td>
  </tr>
  <tr>
   <th width="30%">
    <% multilang("220" "LANG_PORT"); %>:
   </th>
   <td width="70%">
    <input type="text" name="dfromPort" size="4" maxlength="5">-
    <input type="text" name="dtoPort" size="4" maxlength="5">&nbsp;&nbsp;
   </td>
  </tr>
  <tr id="wanif_tr" style="display:none">
   <th width="30%">
    <% multilang("432" "LANG_WAN_INTERFACE"); %>:
   </th>
   <td width="70%">
    <select name="wanif"><% if_wan_list("rt-vpn"); %><% if_wan_list("br"); %></select>
   </td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addFilterIpPort" onClick="return addClick(this)">
 <input type="hidden" value="/fw-ipportfilter.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<form action=/boaform/formFilter method=POST name="formFilterDel">
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p><% multilang("399" "LANG_CURRENT_FILTER_TABLE"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common data_vertical">
  <table>
   <% ipPortFilterList(); %>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="deleteSelFilterIpPort" onClick="return deleteClick(this)">
 <input class="link_bg" type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="deleteAllFilterIpPort" onClick="return deleteAllClick(this)">
 <input type="hidden" value="/fw-ipportfilter.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% checkWrite("ipFilterNum"); %>
</script>
</form>
</body>
</html>
