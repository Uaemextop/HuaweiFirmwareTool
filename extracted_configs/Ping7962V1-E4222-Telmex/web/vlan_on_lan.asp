<%SendWebHeadStr(); %>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>VLAN on LAN <% multilang("245" "LANG_CONFIGURATION"); %></title>
<script>
function saveClick()
{
 if (document.formVLANonLAN.lan1_vid_cap[1].checked == true) {
  if (document.formVLANonLAN.lan1_vid.value == "") {
   alert("<% multilang("2480" "LANG_VID1_SHOULD_NOT_BE_EMPTY"); %>");
   document.formVLANonLAN.lan1_vid.focus();
   return false;
  }
  if (!isNumber(document.formVLANonLAN.lan1_vid.value)) {
   alert("<% multilang("2481" "LANG_VID1_SHOULD_BE_NUMBER"); %>");
   document.formVLANonLAN.lan1_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan1_vid.value >= 7 && document.formVLANonLAN.lan1_vid.value <= 9) {
   alert("<% multilang("2482" "LANG_VID1_7_9_ARE_RESERVED"); %>");
   document.formVLANonLAN.lan1_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan1_vid.value < 0 || document.formVLANonLAN.lan1_vid.value >= 4096) {
   alert("<% multilang("2483" "LANG_VID1_SHOULD_BE_0_4095"); %>");
   document.formVLANonLAN.lan1_vid.focus();
   return false;
  }
 }
 if (document.formVLANonLAN.lan2_vid_cap[1].checked == true) {
  if (document.formVLANonLAN.lan2_vid.value == "") {
   alert("<% multilang("2484" "LANG_VID2_SHOULD_NOT_BE_EMPTY"); %>");
   document.formVLANonLAN.lan2_vid.focus();
   return false;
  }
  if (!isNumber(document.formVLANonLAN.lan2_vid.value)) {
   alert("<% multilang("2485" "LANG_VID2_SHOULD_BE_NUMBER"); %>");
   document.formVLANonLAN.lan2_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan2_vid.value >= 7 && document.formVLANonLAN.lan2_vid.value <= 9) {
   alert("<% multilang("2486" "LANG_VID2_7_9_ARE_RESERVED"); %>");
   document.formVLANonLAN.lan2_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan2_vid.value < 0 || document.formVLANonLAN.lan2_vid.value >= 4096) {
   alert("<% multilang("2487" "LANG_VID2_SHOULD_BE_0_4095"); %>");
   document.formVLANonLAN.lan2_vid.focus();
   return false;
  }
 }
 if (document.formVLANonLAN.lan3_vid_cap[1].checked == true) {
  if (document.formVLANonLAN.lan3_vid.value == "") {
   alert("<% multilang("2488" "LANG_VID3_SHOULD_NOT_BE_EMPTY"); %>");
   document.formVLANonLAN.lan3_vid.focus();
   return false;
  }
  if (!isNumber(document.formVLANonLAN.lan3_vid.value)) {
   alert("<% multilang("2489" "LANG_VID3_SHOULD_BE_NUMBER"); %>");
   document.formVLANonLAN.lan3_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan3_vid.value >= 7 && document.formVLANonLAN.lan3_vid.value <= 9) {
   alert("<% multilang("2490" "LANG_VID3_7_9_ARE_RESERVED"); %>");
   document.formVLANonLAN.lan3_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan3_vid.value < 0 || document.formVLANonLAN.lan3_vid.value >= 4096) {
   alert("<% multilang("2491" "LANG_VID3_SHOULD_BE_0_4095"); %>");
   document.formVLANonLAN.lan3_vid.focus();
   return false;
  }
 }
 if (document.formVLANonLAN.lan4_vid_cap[1].checked == true) {
  if (document.formVLANonLAN.lan4_vid.value == "") {
   alert("<% multilang("2492" "LANG_VID4_SHOULD_NOT_BE_EMPTY"); %>");
   document.formVLANonLAN.lan4_vid.focus();
   return false;
  }
  if (!isNumber(document.formVLANonLAN.lan4_vid.value)) {
   alert("<% multilang("2493" "LANG_VID4_SHOULD_BE_NUMBER"); %>");
   document.formVLANonLAN.lan4_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan4_vid.value >= 7 && document.formVLANonLAN.lan4_vid.value <= 9) {
   alert("<% multilang("2494" "LANG_VID4_7_9_ARE_RESERVED"); %>");
   document.formVLANonLAN.lan4_vid.focus();
   return false;
  }
  if (document.formVLANonLAN.lan4_vid.value < 0 || document.formVLANonLAN.lan4_vid.value >= 4096) {
   alert("<% multilang("2495" "LANG_VID4_SHOULD_BE_0_4095"); %>");
   document.formVLANonLAN.lan4_vid.focus();
   return false;
  }
 }
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
function updateState()
{
 if (document.formVLANonLAN.lan1_vid_cap[1].checked)
  enableTextField(document.formVLANonLAN.lan1_vid);
 else
  disableTextField(document.formVLANonLAN.lan1_vid);
 if (document.formVLANonLAN.lan2_vid_cap[1].checked)
  enableTextField(document.formVLANonLAN.lan2_vid);
 else
  disableTextField(document.formVLANonLAN.lan2_vid);
 if (document.formVLANonLAN.lan3_vid_cap[1].checked)
  enableTextField(document.formVLANonLAN.lan3_vid);
 else
  disableTextField(document.formVLANonLAN.lan3_vid);
 if (document.formVLANonLAN.lan4_vid_cap[1].checked)
  enableTextField(document.formVLANonLAN.lan4_vid);
 else
  disableTextField(document.formVLANonLAN.lan4_vid);
}
</script>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title">VLAN on LAN <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("431" "LANG_THIS_PAGE_BE_USED_TO_CONFIGURE_VLAN_ON_LAN"); %></p>
</div>
<form action=/boaform/formVLANonLAN method=POST name="formVLANonLAN">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th>LAN1 <% multilang("293" "LANG_VLAN"); %> <% multilang("698" "LANG_ID"); %>: </th>
   <td><input type="text" name="lan1_vid" size="10" maxlength="15" value=<% getInfo("lan1-vid"); %>></td>
   <td>
   <input type="radio" value="0" name="lan1_vid_cap" <% checkWrite("lan1-vid-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
   <input type="radio" value="1" name="lan1_vid_cap" <% checkWrite("lan1-vid-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>&nbsp;&nbsp;
   </td>
  </tr>
  <tr>
   <th>LAN2 <% multilang("293" "LANG_VLAN"); %> <% multilang("698" "LANG_ID"); %>: </th>
   <td><input type="text" name="lan2_vid" size="10" maxlength="15" value=<% getInfo("lan2-vid"); %>></td>
   <td>
   <input type="radio" value="0" name="lan2_vid_cap" <% checkWrite("lan2-vid-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
   <input type="radio" value="1" name="lan2_vid_cap" <% checkWrite("lan2-vid-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>&nbsp;&nbsp;
   </td>
  </tr>
  <tr>
   <th>LAN3 <% multilang("293" "LANG_VLAN"); %> <% multilang("698" "LANG_ID"); %>: </th>
   <td><input type="text" name="lan3_vid" size="10" maxlength="15" value=<% getInfo("lan3-vid"); %>></td>
   <td>
   <input type="radio" value="0" name="lan3_vid_cap" <% checkWrite("lan3-vid-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
   <input type="radio" value="1" name="lan3_vid_cap" <% checkWrite("lan3-vid-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>&nbsp;&nbsp;
   </td>
  </tr>
  <tr>
   <th>LAN4 <% multilang("293" "LANG_VLAN"); %> <% multilang("698" "LANG_ID"); %>: </th>
   <td><input type="text" name="lan4_vid" size="10" maxlength="15" value=<% getInfo("lan4-vid"); %>></td>
   <td>
   <input type="radio" value="0" name="lan4_vid_cap" <% checkWrite("lan4-vid-cap0"); %> onClick="updateState()"><% multilang("254" "LANG_DISABLE"); %>&nbsp;&nbsp;
   <input type="radio" value="1" name="lan4_vid_cap" <% checkWrite("lan4-vid-cap1"); %> onClick="updateState()"><% multilang("255" "LANG_ENABLE"); %>&nbsp;&nbsp;
   </td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" type="submit" value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" onClick="return saveClick()">
 <input type="hidden" value="/vlan_on_lan.asp" name="submit-url">
 <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>updateState();</script>
</form>
</body>
</html>
