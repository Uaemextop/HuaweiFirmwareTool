<% SendWebHeadStr();%>
<title><% multilang("224" "LANG_WLAN_ACCESS_CONTROL"); %></title>
<script>
function skip () { this.blur(); }
function addClick(obj)
{
 if (!checkMac(document.formWlAcAdd.mac, 1))
  return false;
 obj.isclick = 1;
 postTableEncrypt(document.formWlAcAdd.postSecurityFlag, document.formWlAcAdd);
 return true;
}
function disableDelButton()
{
 disableButton(document.formWlAcDel.deleteSelFilterMac);
 disableButton(document.formWlAcDel.deleteAllFilterMac);
}
function enableAc()
{
  enableTextField(document.formWlAcAdd.mac);
}
function disableAc()
{
  disableTextField(document.formWlAcAdd.mac);
}
function updateState()
{
  if(wlanDisabled || wlanMode == 1 || wlanMode ==2){
 disableDelButton();
 disableButton(document.formWlAcAdd.reset);
 disableButton(document.formWlAcAdd.setFilterMode);
 disableButton(document.formWlAcAdd.addFilterMac);
   disableTextField(document.formWlAcAdd.wlanAcEnabled);
   disableAc();
  }
  else{
    if (document.formWlAcAdd.wlanAcEnabled.selectedIndex) {
 enableButton(document.formWlAcAdd.reset);
 enableButton(document.formWlAcAdd.addFilterMac);
  enableAc();
    }
    else {
 disableButton(document.formWlAcAdd.reset);
 disableButton(document.formWlAcAdd.addFilterMac);
   disableAc();
    }
  }
}
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.formWlAcAdd.postSecurityFlag, document.formWlAcAdd);
 return true;
}
function deleteClick(obj)
{
 if ( !confirm('<% multilang("1753" "LANG_CONFIRM_DELETE_ONE_ENTRY"); %>') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.formWlAcDel.postSecurityFlag, document.formWlAcDel);
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
  postTableEncrypt(document.formWlAcDel.postSecurityFlag, document.formWlAcDel);
  return true;
 }
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("224" "LANG_WLAN_ACCESS_CONTROL"); %></p>
 <p class="intro_content"><% multilang("225" "LANG_PAGE_DESC_WLAN_ALLOW_DENY_LIST"); %></p>
</div>
<form action=/boaform/admin/formWlAc method=POST name="formWlAcAdd">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%">
    <% multilang("143" "LANG_MODE"); %>: &nbsp;&nbsp;&nbsp;&nbsp;
   </th>
   <td>
   <select size="1" name="wlanAcEnabled" onclick="updateState()">
    <option value=0 ><% multilang("186" "LANG_DISABLED"); %></option>
    <option value=1 selected ><% multilang("226" "LANG_ALLOW_LISTED"); %></option>
    <option value=2 ><% multilang("227" "LANG_DENY_LISTED"); %></option>
   </select>
   </td>
   <td><input type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="setFilterMode" class="inner_btn" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("92" "LANG_MAC_ADDRESS"); %>: </th>
   <td>
    <input type="text" name="mac" size="15" maxlength="12">&nbsp;&nbsp;(ex. 00E086710502)
   </td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addFilterMac" onClick="return addClick(this)" class="link_bg">&nbsp;&nbsp;
 <input type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset" class="link_bg">&nbsp;&nbsp;&nbsp;
 <input type="hidden" value="/admin/wlactrl.asp" name="submit-url">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<form action=/boaform/admin/formWlAc method=POST name="formWlAcDel">
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p><% multilang("230" "LANG_CURRENT_ACCESS_CONTROL_LIST"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common data_vertical">
  <table border="0" width=440>
   <% wlAcList(); %>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <input type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="deleteSelFilterMac" onClick="return deleteClick(this)" class="link_bg">&nbsp;&nbsp;
 <input type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="deleteAllFilterMac" onClick="return deleteAllClick(this)" class="link_bg">&nbsp;&nbsp;&nbsp;
 <input type="hidden" value="/admin/wlactrl.asp" name="submit-url">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% checkWrite("wlanAcNum"); %>
 <% initPage("wlactrl"); %>
 updateState();
</script>
<br><br>
</form>
</body>
</html>
