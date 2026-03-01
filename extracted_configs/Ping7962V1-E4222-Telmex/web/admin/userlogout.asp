<%SendWebHeadStr(); %>
<title><% multilang("63" "LANG_LOGOUT"); %></title>
<SCRIPT>
function confirmuserlogout(obj)
{
   if ( !confirm('<% multilang("2565" "LANG_DO_YOU_CONFIRM_TO_LOGOUT"); %>') ) {
 return false;
  }
  else{
   obj.isclick = 1;
 postTableEncrypt(document.forms[0].postSecurityFlag, document.forms[0]);
 return true;
  }
}
</SCRIPT>
</head>
<body>
<div class="intro_main ">
 <p class="intro_title"><% multilang("63" "LANG_LOGOUT"); %></p>
 <p class="intro_content"> <% multilang("811" "LANG_THIS_PAGE_IS_USED_TO_LOGOUT_FROM_THE_DEVICE"); %></p>
</div>
<form action=/boaform/admin/formUserLogout method=POST name="cmuserlogout">
<div class="btn_ctl">
      <input type="submit" value="<% multilang("63" "LANG_LOGOUT"); %>" name="userlogout" onclick="return confirmuserlogout(this)">&nbsp;&nbsp;
      <input type="hidden" value="/admin/userlogout.asp" name="submit-url">
      <input type="hidden" name="postSecurityFlag" value="">
</div>
</form>
</body>
</html>
