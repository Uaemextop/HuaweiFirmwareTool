<%SendWebHeadStr(); %>
<title><% multilang("3042" "LANG_MPTCP"); %> <% multilang("245" "LANG_CONFIGURATION"); %></title>
<SCRIPT>
function checkChange(cb)
{
 if(cb.checked==true){
  cb.value = 1;
 }
 else{
  cb.value = 0;
 }
}
function saveChanges(obj)
{
 if ( checkDigit(document.mptcp.syncretry.value) == 0) {
  alert("<% multilang("3053" "LANG_STRINVDRETRY"); %>");
  document.mptcp.syncretry.focus();
  return false;
 }
 obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("3042" "LANG_MPTCP"); %> <% multilang("245" "LANG_CONFIGURATION"); %></p>
 <p class="intro_content"> <% multilang("3043" "LANG_THIS_PAGE_LET_USER_TO_CONFIG_MPTCP"); %></p>
</div>
<form action=/boaform/formMptcp method=POST name="mptcp">
<div class="data_common data_common_notitle">
 <table>
  <tr>
   <th width="30%"><% multilang("255" "LANG_ENABLE"); %>:</th>
   <td width="70%"><input type="checkbox" name="enable" value="1" onChange="checkChange(this)"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3044" "LANG_PATHMANGER"); %>:</th>
   <td>
    <select name="path_manger">
     <option value=0><% multilang("1070" "LANG_DEFAULT"); %></option>
     <option value=1><% multilang("3045" "LANG_FULLMESH"); %></option>
     <option value=2><% multilang("3046" "LANG_NDIFFPORTS"); %></option>
     <option value=3><% multilang("3047" "LANG_BINDER"); %></option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3051" "LANG_CHECKSUM"); %>:</th>
   <td width="70%"><input type="checkbox" name="mptcpchecksum" value="1" onChange="checkChange(this)"></td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3048" "LANG_SCHEDULER"); %>:</th>
   <td>
    <select name="scheduler">
     <option value=0><% multilang("1070" "LANG_DEFAULT"); %></option>
     <option value=1><% multilang("3049" "LANG_ROUNDROBIN"); %></option>
     <option value=2><% multilang("3050" "LANG_REDUNANT"); %></option>
    </select>
   </td>
  </tr>
  <tr>
   <th width="30%"><% multilang("3052" "LANG_SYNCRETRY"); %>:</th>
   <td width="70%"><input type="text" name="syncretry" size=10 maxlength=9 value="3"></td>
  </tr>
 </table>
</div>
<div class="btn_ctl">
      <input class="link_bg" type=submit value="<% multilang("159" "LANG_APPLY_CHANGES"); %>" name="save" onClick="return saveChanges(this)">
      <input type=hidden value="/mptcp.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
<script>
 <% ShowMptcpPage(); %>
</script>
</form>
</body>
</html>
