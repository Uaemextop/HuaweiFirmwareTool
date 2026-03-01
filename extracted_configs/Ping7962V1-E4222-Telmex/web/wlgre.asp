<% SendWebHeadStr();%>
<title><% multilang_old("WLAN GRE Settings"); %></title>
<style>
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript" src="share.js"> </script>
<script>
function fon_control(){
 if(document.getElementById("fon_enable").checked) {
  document.getElementById("fon_content").style.display = "block";
  document.getElementById("fon_status").style.display = "block";
 }else {
  document.getElementById("fon_content").style.display = "none";
  document.getElementById("fon_status").style.display = "none";
 }
}
function fon_free_control(){
 if(document.fon.fon_enable1.checked == true)
 {
  enableTextField(document.fon.ssid1);
  enableTextField(document.fon.wlanGw1);
  enableTextField(document.fon.vlantag1);
 }else
 {
  disableTextField(document.fon.ssid1);
  disableTextField(document.fon.wlanGw1);
  disableTextField(document.fon.vlantag1);
 }
}
function fon_eap_control(){
 if(document.fon.fon_enable2.checked == true)
 {
  enableTextField(document.fon.ssid2);
  enableTextField(document.fon.wlanGw2);
  enableTextField(document.fon.vlantag2);
  enableTextField(document.fon.radiusPort);
  enableTextField(document.fon.radiusIP);
  enableTextField(document.fon.radiusPass);
 }else
 {
  disableTextField(document.fon.ssid2);
  disableTextField(document.fon.wlanGw2);
  disableTextField(document.fon.vlantag2);
  disableTextField(document.fon.radiusPort);
  disableTextField(document.fon.radiusIP);
  disableTextField(document.fon.radiusPass);
 }
}
function callEachElement(elements, className, callback) {
  if (typeof className === 'function') {
   callback = className;
   className = '';
  }
  var flag = false;
  for (var i = 0, length = elements.length; i < length; i++) {
   if (!className || elements[i].className.indexOf(className) > -1) {
    flag = callback.call(elements[i]);
    if (typeof flag != 'undefined') {
     if (flag) {
      continue;
     } else {
      break;
     }
    }
   }
  }
 return flag;
 }
 function validate(form, classname) {
  return callEachElement(form.elements, classname, function() {
   var value = this.value;
   var flag = true;
   if (!value) return flag;
   if (parseInt(value) != value) {
    return flag = false;
   } else {
    if (value < 0 || value > 4095) {
     return flag = false;
    }
   }
   return flag;
  });
 }
 window.onload = function() {
  var form = document.fon;
  form.onsubmit = function() {
   if(document.fon.fon_enable.checked==true) {
    if(document.fon.fon_enable1.checked==true) {
     if (!validate(this,'vlantag_field1')) {
      alert('vlantag should be 0~4095!');
      document.fon.vlantag1.focus();
      return false;
     }
     if(document.fon.wlanGw1.value==""){
      alert("Invalid Endpoint!");
      document.fon.wlanGw1.focus();
      return false;
     }
    }
    if(document.fon.fon_enable2.checked==true) {
     if(validateKey(document.fon.radiusPort.value)){
      rsport = parseInt(document.fon.radiusPort.value);
      if(rsport<=0||rsport>65535){
       alert('radius port should be 1~65535!');
       document.fon.radiusPort.focus();
       return false;
      }
     }else{
       alert('radius port should be 1~65535!');
       document.fon.radiusPort.focus();
       return false;
     }
     if (!checkIP(document.fon.radiusIP)) {
      alert('Invalid radius IP.');
      document.fon.radiusIP.focus();
      return false;
     }
     if (!validate(this,'vlantag_field2')) {
      alert('vlantag should be 0~4095!');
      document.fon.vlantag2.focus();
      return false;
     }
     if(document.fon.radiusPass.value==""){
      alert("Invalid Password!");
      document.fon.radiusPass.focus();
      return false;
     }
     if(document.fon.wlanGw2.value==""){
      alert("Invalid Endpoint!");
      document.fon.wlanGw2.focus();
      return false;
     }
    }
    if(document.fon.fon_enable1.checked==false && document.fon.fon_enable2.checked==false)
    {
     alert('FON is enabled, you should enable at least one ssid!');
     return false;
    }
   }
   return true;
  }
 }
</SCRIPT>
</head>
<body>
<div class="intro_main ">
<p class="intro_title">WLAN GRE Settings</p>
<p class="intro_content">This page allows you setup GRE.</p>
</div>
<form action=/boaform/formFonGre method=POST name="fon">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%">GRE Enable&nbsp;&nbsp;&nbsp;&nbsp;</th>
   <td>
     <input id="fon_enable" type="checkbox" name="fon_enable" onclick="javascript:fon_control()">
   </td>
  </tr>
 </table>
</div>
<div class="data_common data_common_notitle" id="fon_content" style="display:none">
 <table>
  <tr>
   <th width="100%" colspan=3>
    GRE FREE SSID Settings
   </th>
  </tr>
    <tr>
    <th width="30%">Name</th>
    <td>
        <input id="grename1" type="text" name="grename1" maxlength="14" readonly>
    </td>
   </tr>
   <tr>
    <th>Enable</th>
    <td>
        <input id="fon_enable1" type="checkbox" name="fon_enable1" onclick="javascript:fon_free_control()">
    </td>
   </tr>
   <tr>
    <th>SSID</th>
    <td>
     <input type="text" maxlength="32" size="32" name="ssid1">
    </td>
   </tr>
   <tr>
    <th>GRE Endpoint</th>
    <td>
     <input type="text" name="wlanGw1" id="wlanGw1" size="25" maxlength="32" >
    </td>
   </tr>
   <tr>
    <th>VLAN Tag</th>
    <td>
     <input type="text" maxlength="32" size="25" id="vlantag1" name="vlantag1" class="vlantag_field1">(0-4095)
    </td>
   </tr>
 </table>
 <table>
  <tr>
   <th width="100%" colspan=3>
    CLOSED SSID Settings
   </th>
  </tr>
    <tr>
    <th width="30%">Name</th>
    <td>
        <input id="grename2" type="text" name="grename2" maxlength="14" readonly>
    </td>
   </tr>
   <tr>
    <th>Enable</th>
    <td>
        <input id="fon_enable2" type="checkbox" name="fon_enable2" onclick="javascript:fon_eap_control()">
    </td>
   </tr>
   <tr>
    <th>SSID</th>
    <td>
     <input type="text" maxlength="32" size="32" name="ssid2">
    </td>
   </tr>
      <tr>
    <th>RADIUS Server</th>
    <td>
     Port<input type="text" maxlength="5" size="4" name="radiusPort">
     &nbsp;&nbsp;
             IP address<input type="text" size="16" name="radiusIP"> &nbsp;&nbsp;
             Password<input type="password" maxlength="64" size="8" name="radiusPass">
    </td>
   </tr>
   <tr>
    <th>GRE Endpoint</th>
    <td>
     <input type="text" name="wlanGw2" id="wlanGw2" size="25" maxlength="32" >
    </td>
   </tr>
   <tr>
    <th>VLAN Tag</th>
    <td>
     <input type="text" maxlength="32" size="25" id="vlantag2" name="vlantag2" class="vlantag_field2">(0-4095)
    </td>
   </tr>
 </table>
</div>
<div class="btn_ctl">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
 <input type=hidden value="/wlgre.asp" name="submit-url">
 <input type=submit value="Apply Changes" id="save"name="save" onClick="return saveChanges()" class="link_bg">&nbsp;
</div>
<div class="column" id="fon_status" style="display:none">
 <div class="column_title">
  <div class="column_title_left"></div>
      <p>GRE Connection Status:</p>
  <div class="column_title_right"></div>
 </div>
 <div class="data_common data_vertical">
  <table>
   <tr>
    <th width="30%">GRE Connection Status</th>
    <td id="fonstatus"></td>
   </tr>
  </table>
 </div>
</div>
<script>
  <% initPage("wlgre"); %>
  <% initPage("wlgrestatus"); %>
  fon_control();
  fon_free_control();
  fon_eap_control();
</script>
</form>
</body>
</html>
