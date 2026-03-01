<%SendWebHeadStr(); %>
<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>
<title>WDS <% multilang("383" "LANG_SETTINGS"); %></title>
<script>
function addClick(obj)
{
 if (!checkMac(document.formWlWdsAdd.mac, 1))
  return false;
 if (checkString(document.formWlWdsAdd.comment.value) == 0) {
  alert("<% multilang("2532" "LANG_INVALID_COMMENT"); %>");
  document.formWlWdsAdd.comment.focus();
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.formWlWdsAdd.postSecurityFlag, document.formWlWdsAdd);
 return true;
}
function disableDelButton()
{
 disableButton(document.formWlWdsDel.deleteSelWdsMac);
 disableButton(document.formWlWdsDel.deleteAllWdsMac);
}
function enableWds()
{
  enableTextField(document.formWlWdsAdd.mac);
  enableTextField(document.formWlWdsAdd.comment);
}
function disableWds()
{
  disableTextField(document.formWlWdsAdd.mac);
  disableTextField(document.formWlWdsAdd.comment);
}
function updateState()
{
 if (document.formWlWdsAdd.wlanDisabled.value == "ON") {
  disableTextField(document.formWlWdsAdd.wlanWdsEnabled);
  disableButton(document.formWlWdsAdd.reset);
  disableButton(document.formWlWdsAdd.addWdsMac);
  disableButton(document.formWlWdsAdd.wdsSet);
  disableWds();
  disableDelButton();
 } else {
  if(document.formWlWdsAdd.wlanWdsEnabled.disabled == true){
   disableButton(document.formWlWdsAdd.reset);
   disableButton(document.formWlWdsAdd.addWdsMac);
   disableButton(document.formWlWdsAdd.wdsSet);
   disableWds();
   disableDelButton();
  }else{
   if (document.formWlWdsAdd.wlanWdsEnabled.checked) {
    enableButton(document.formWlWdsAdd.reset);
    enableButton(document.formWlWdsAdd.addWdsMac);
    enableWds();
   }
   else {
    disableButton(document.formWlWdsAdd.reset);
    disableButton(document.formWlWdsAdd.addWdsMac);
    disableWds();
   }
  }
 }
}
function openWindow(url, windowName, w, h) {
 var wide=w;
 var high=h;
 if (document.all)
  var xMax = screen.width, yMax = screen.height;
 else if (document.layers)
  var xMax = window.outerWidth, yMax = window.outerHeight;
 else
    var xMax = 640, yMax=500;
 var xOffset = (xMax - wide)/2;
 var yOffset = (yMax - high)/3;
 var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';
 window.open( url, windowName, settings );
}
function showApClick(url)
{
  if (document.formWlWdsAdd.wlanWdsEnabled.checked)
 openWindow(url, 'showWdsStatistics',620,440 );
}
function showWepClick(url)
{
  if (document.formWlWdsAdd.wlanWdsEnabled.checked){
 openWindow(url, 'showWdsWep',620,340 );
  }
}
function on_submit(obj)
{
 obj.isclick = 1;
 postTableEncrypt(document.formWlWdsAdd.postSecurityFlag, document.formWlWdsAdd);
 return true;
}
function deleteClick(obj)
{
 if ( !confirm('<% multilang("1753" "LANG_CONFIRM_DELETE_ONE_ENTRY"); %>') ) {
  return false;
 }
 else{
  obj.isclick = 1;
  postTableEncrypt(document.formWlWdsDel.postSecurityFlag, document.formWlWdsDel);
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
  postTableEncrypt(document.formWlWdsDel.postSecurityFlag, document.formWlWdsDel);
  return true;
 }
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">WDS <% multilang("383" "LANG_SETTINGS"); %></p>
 <p class="intro_content"> <% multilang("721" "LANG_WIRELESS_DISTRIBUTION_SYSTEM_USES_WIRELESS_MEDIA_TO_COMMUNICATE_WITH_OTHER_APS_LIKE_THE_ETHERNET_DOES_TO_DO_THIS_YOU_MUST_SET_THESE_APS_IN_THE_SAME_CHANNEL_AND_SET_MAC_ADDRESS_OF_OTHER_APS_WHICH_YOU_WANT_TO_COMMUNICATE_WITH_IN_THE_TABLE_AND_THEN_ENABLE_THE_WDS"); %></p>
</div>
<form action=/boaform/admin/formWlWds method=POST name="formWlWdsAdd">
<div class="data_common data_common_notitle">
 <table>
  <input type=hidden name="wlanDisabled" value=<% wlanStatus(); %>>
  <tr>
     <th>
     <input type="checkbox" name="wlanWdsEnabled" value="ON" <% checkWrite("wlanWdsEnabled"); %> onclick="updateState()">&nbsp;&nbsp;<% multilang("255" "LANG_ENABLE"); %> WDS</th>
     <td><input class="inner_btn" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="wdsSet" onClick="return on_submit(this)">&nbsp;&nbsp;</td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th><% multilang("92" "LANG_MAC_ADDRESS"); %>:</th>
   <td><input type="text" name="mac" size="15" maxlength="12"></td>
  </tr>
  <tr id="wds_txrate" <% checkWrite("wlan_qtn_hidden_function"); %>>
   <th><% multilang("175" "LANG_DATA_RATE"); %>:</th>
   <td><select size="1" name="txRate" onChange="">
    <SCRIPT>
    <% checkWrite("wl_txRate"); %>
     rate_mask = [15,1,1,1,1,2,2,2,2,2,2,2,2,4,4,4,4,4,4,4,4,8,8,8,8,8,8,8,8];
     rate_name = ["<% multilang("176" "LANG_AUTO"); %>","1M","2M","5.5M","11M","6M","9M","12M","18M","24M","36M","48M","54M", "MCS0", "MCS1" , "MCS2", "MCS3", "MCS4", "MCS5", "MCS6",
     "MCS7", "MCS8", "MCS9", "MCS10", "MCS11", "MCS12", "MCS13", "MCS14", "MCS15"];
     vht_rate_name=["NSS1-MCS0","NSS1-MCS1","NSS1-MCS2","NSS1-MCS3","NSS1-MCS4",
     "NSS1-MCS5","NSS1-MCS6","NSS1-MCS7","NSS1-MCS8","NSS1-MCS9",
     "NSS2-MCS0","NSS2-MCS1","NSS2-MCS2","NSS2-MCS3","NSS2-MCS4",
     "NSS2-MCS5","NSS2-MCS6","NSS2-MCS7","NSS2-MCS8","NSS2-MCS9"];
     mask = 0;
     if (auto)
      txrate=0;
     if (band & 1)
      mask |= 1;
     if ((band&2) || (band&4))
      mask |= 2;
     if (band & 8)
     {
      if (rf_num == 2)
       mask |= 12;
      else
       mask |= 4;
     }
     defidx = 0;
     for (idx=0, i=0; i<rate_name.length; i++)
     {
      if (rate_mask[i] & mask)
      {
       if (i == 0)
        rate = 0;
       else
        rate = (1 << (i-1));
       if (txrate == rate)
        defidx = idx;
       document.write('<option value="' + i + '">' + rate_name[i] + '\n');
       idx++;
      }
     }
     if(band & 64){
      for (i=0; i<vht_rate_name.length; i++) {
       rate = (((1 << 31)>>>0) + i);
       if (txrate == rate)
        defidx = idx;
       if(chanwid!=0 || (i!=9 && i!=19))
       {
        document.write('<option value="' + (i+30) + '">' + vht_rate_name[i] + '\n');
        idx++;
       }
      }
     }
     document.formWlWdsAdd.elements["txRate"].selectedIndex = defidx;
    </SCRIPT>
   </select>
   </td>
  </tr>
  <tr <% checkWrite("wlan_qtn_hidden_function"); %>>
   <th><% multilang("406" "LANG_COMMENT"); %>:</th>
   <td><input type="text" name="comment" size="16" maxlength="19"></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("228" "LANG_ADD"); %>" name="addWdsMac" onClick="return addClick(this)">&nbsp;&nbsp;
 <input class="link_bg" type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset">&nbsp;&nbsp;&nbsp;&nbsp;
 <input class="link_bg" type="button" value="<% multilang("722" "LANG_SET_SECURITY"); %>" name="showWep" onClick="showWepClick('/wlwdsenp.asp')">&nbsp;&nbsp;
 <input class="link_bg" type="button" value="<% multilang("723" "LANG_SHOW_STATISTICS"); %>" name="showAp" onClick="showApClick('/wlwdstbl.asp')">&nbsp;&nbsp;
 <input type="hidden" value="/admin/wlwds.asp" name="submit-url">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
<form action=/boaform/admin/formWlWds method=POST name="formWlWdsDel">
<div class="column">
 <div class="column_title">
  <div class="column_title_left"></div>
   <p><% multilang("724" "LANG_CURRENT_WDS_AP_LIST"); %></p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common">
  <table>
   <% wlWdsList(); %>
  </table>
 </div>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("231" "LANG_DELETE_SELECTED"); %>" name="deleteSelWdsMac" onClick="return deleteClick(this)">&nbsp;&nbsp;
 <input class="link_bg" type="submit" value="<% multilang("232" "LANG_DELETE_ALL"); %>" name="deleteAllWdsMac" onClick="return deleteAllClick(this)">&nbsp;&nbsp;&nbsp;
 <input class="link_bg" type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset">
 <input type="hidden" value="/admin/wlwds.asp" name="submit-url">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% initPage("wlwds"); %>
 updateState();
 <% checkWrite("wlanWDSNum"); %>
</script>
</form>
</body>
</html>
