<%SendWebHeadStr(); %>
<title>WAPI <% multilang("10" "LANG_CERTIFICATION_INSTALLATION"); %></title>
<style>
.on {display:on}
.off {display:none}
</style>
<script type="text/javascript" src="util_gw.js"></script>
<script>
var MWJ_progBar = 0;
var time=0;
var delay_time=1000;
var loop_num=0;
function progress()
{
  if (loop_num == 3) {
 alert("<% multilang("2526" "LANG_UPDATE_FIRMWARE_FAILED"); %>");
 return false;
  }
  if (time < 1)
 time = time + 0.033;
  else {
 time = 0;
 loop_num++;
  }
  setTimeout('progress()',delay_time);
  myProgBar.setBar(time);
}
function getRefToDivNest(divID, oDoc)
{
  if( !oDoc ) { oDoc = document; }
  if( document.layers ) {
 if( oDoc.layers[divID] ) { return oDoc.layers[divID]; } else {
 for( var x = 0, y; !y && x < oDoc.layers.length; x++ ) {
  y = getRefToDivNest(divID,oDoc.layers[x].document); }
 return y; } }
  if( document.getElementById ) { return document.getElementById(divID); }
  if( document.all ) { return document.all[divID]; }
  return document[divID];
}
function sendClicked(F)
{
  if(document.uploadCert.asu_binary.value == "" && document.uploadCert==F){
       document.uploadCert.asu_binary.focus();
   alert("<% multilang("2527" "LANG_FILE_NAME_CAN_NOT_BE_EMPTY"); %>");
   return false;
  }
  if(document.uploadUserCert.user_binary.value == "" && document.uploadUserCert==F){
       document.uploadUserCert.user_binary.focus();
   alert("<% multilang("2527" "LANG_FILE_NAME_CAN_NOT_BE_EMPTY"); %>");
   return false;
  }
  F.submit();
  show_div(true, "progress_div");
  progress();
}
function show_div(show,id) {
 if(show)
  document.getElementById(id).className = "on" ;
     else
      document.getElementById(id).className = "off" ;
}
function resetBar( a, b )
{
  this.amt = ( typeof( b ) == 'undefined' ) ? a : b ? ( this.amt + a ) : ( this.amt - a );
  if( isNaN( this.amt ) ) { this.amt = 0; } if( this.amt > 1 ) { this.amt = 1; } if( this.amt < 0 ) { this.amt = 0; }
  var theWidth = Math.round( this.width * ( ( this.dir % 2 ) ? this.amt : 1 ) );
  var theHeight = Math.round( this.height * ( ( this.dir % 2 ) ? 1 : this.amt ) );
  var theDiv = getRefToDivNest( this.id ); if( !theDiv ) { window.status = 'Progress: ' + Math.round( 100 * this.amt ) + '%'; return; }
  if( theDiv.style ) { theDiv = theDiv.style; theDiv.clip = 'rect(0px '+theWidth+'px '+theHeight+'px 0px)'; }
  var oPix = document.childNodes ? 'px' : 0;
  theDiv.width = theWidth + oPix; theDiv.pixelWidth = theWidth; theDiv.height = theHeight + oPix; theDiv.pixelHeight = theHeight;
  if( theDiv.resizeTo ) { theDiv.resizeTo( theWidth, theHeight ); }
  theDiv.left = ( ( this.dir != 3 ) ? 0 : this.width - theWidth ) + oPix; theDiv.top = ( ( this.dir != 4 ) ? 0 : this.height - theHeight ) + oPix;
}
function setColour( a )
{
  var theDiv = getRefToDivNest( this.id ); if( theDiv.style ) { theDiv = theDiv.style; }
  theDiv.bgColor = a; theDiv.backgroundColor = a; theDiv.background = a;
}
function progressBar( oBt, oBc, oBg, oBa, oWi, oHi, oDr )
{
  MWJ_progBar++; this.id = 'MWJ_progBar' + MWJ_progBar; this.dir = oDr; this.width = oWi; this.height = oHi; this.amt = 0;
  document.write( '<span id = "progress_div" class = "off" > <table border="0" cellspacing="0" cellpadding="'+oBt+'">'+
        '<tr><td>Please wait...</td></tr><tr><td bgcolor="'+oBc+'">'+
                '<table border="0" cellspacing="0" cellpadding="0"><tr><td height="'+oHi+'" width="'+oWi+'" bgcolor="'+oBg+'">' );
  if( document.layers ) {
        document.write( '<ilayer height="'+oHi+'" width="'+oWi+'"><layer bgcolor="'+oBa+'" name="MWJ_progBar'+MWJ_progBar+'"></layer></ilayer>' );
  } else {
        document.write( '<div style="position:relative;top:0px;left:0px;height:'+oHi+'px;width:'+oWi+';">'+
                        '<div style="position:absolute;top:0px;left:0px;height:0px;width:0;font-size:1px;background-color:'+oBa+';" id="MWJ_progBar'+MWJ_progBar+'"></div></div>' );
  }
  document.write( '</td></tr></table></td></tr></table></span>\n' );
  this.setBar = resetBar;
  this.setCol = setColour;
}
</script>
</head>
<BODY>
<div class="intro_main ">
 <p class="intro_title">WAPI <% multilang("10" "LANG_CERTIFICATION_INSTALLATION"); %></p>
 <p class="intro_content"> <% multilang("719" "LANG_THIS_PAGE_ALLOWS_YOU_TO_INSTALL_ASU_AND_USER_CERTIFICATION_FOR_YOUR_DEVICE_PLEASE_NOTE_CERTIFICATION_TYPE_X_509_IS_SUPPORTED_AT_PRESENT"); %></p>
</div>
<form method="post" action="/boaform/formUploadWapiCert1" enctype="multipart/form-data" name="uploadCert">
<div class="data_common data_common_notitle">
 <table>
 <!--
 <tr>
 <td width="20%"><font size=2><b>Certification Type:</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
 <td width="80%"><font size=2> <input name="cert_type" type=radio value=0 checked>X.509</td>
 </tr>
 -->
  <tr>
    <th>ASU <% multilang("720" "LANG_CERTIFICATION"); %>:&nbsp;&nbsp;&nbsp;&nbsp;</th>
    <td><input type="file" value=<% multilang("546" "LANG_CHOOSE_FILE"); %> name="asu_binary" size=20></td>
  </tr>
 <!-- <tr>
   <td width="20%"><font size=2><b>User Certification:</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
   <td width="80%"><font size=2><input type="file" name="user_binary" size=20></td>
 </tr>
 -->
 </table>
</div>
<div class="btn_ctl">
    <input class="link_bg" onclick=sendClicked(this.form) type=button value="<% multilang("595" "LANG_UPLOAD"); %>" name="send">&nbsp;&nbsp;
 <input class="link_bg" type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
<!--
 <input type="hidden" value="0x10000" name="writeAddrWebPages">
 <input type="hidden" value="0x20000" name="writeAddrCode">
-->
<!--
 <input type="hidden" value="/wlwapiinstallcert.asp" name="submit-url">
        <input type="hidden" value="asu" name="uploadcerttype">
-->
</div>
</form>
<form method="post" action="/boaform/formUploadWapiCert2" enctype="multipart/form-data" name="uploadUserCert">
<div class="data_common data_common_notitle">
 <table>
 <!--
 <tr>
 <td width="20%"><font size=2><b>Certification Type:</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
 <td width="80%"><font size=2> <input name="cert_type" type=radio value=0 checked>X.509</td>
 </tr>
 <tr>
   <td width="20%"><font size=2><b>ASU Certification:</b>&nbsp;&nbsp;&nbsp;&nbsp;</td>
   <td width="80%"><font size=2><input type="file" name="asu_binary" size=20></td>
 </tr>
 -->
  <tr>
    <th>User <% multilang("720" "LANG_CERTIFICATION"); %>:&nbsp;&nbsp;&nbsp;&nbsp;</th>
    <td><input type="file" value=<% multilang("546" "LANG_CHOOSE_FILE"); %> name="user_binary" size=20></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
 <input class="link_bg" onclick=sendClicked(this.form) type=button value="<% multilang("595" "LANG_UPLOAD"); %>" name="send">&nbsp;&nbsp;
 <input class="link_bg" type="reset" value="<% multilang("229" "LANG_RESET"); %>" name="reset">
 <input type="hidden" name="wlan_idx" value=<% checkWrite("wlan_idx"); %>>
<!--
        <input type="hidden" value="0x10000" name="writeAddrWebPages">
        <input type="hidden" value="0x20000" name="writeAddrCode">
-->
<!--
        <input type="hidden" value="/wlwapiinstallcert.asp" name="submit-url">
        <input type="hidden" value="user" name="uploadcerttype">
 -->
</div>
</form>
 <script type="text/javascript" language="javascript1.2">
  var myProgBar = new progressBar(
   1,
   '#000000',
   '#ffffff',
   '#043db2',
   300,
   15,
   1
  );
</script>
 </blockquote>
</body>
</html>
