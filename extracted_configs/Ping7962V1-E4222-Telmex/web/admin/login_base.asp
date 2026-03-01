<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<script type="text/javascript" src="rollups/md5.js"></script>
<script type="text/javascript" src="php-crypt-md5.js"></script>
<SCRIPT language="javascript" src="/common.js"></SCRIPT>
<SCRIPT>
function createCaptcha() {
  var code;
  var canv = document.createElement("canvas");
  canv.id = "captcha";
  canv.width = 100;
  canv.height = 30;
  var ctx = canv.getContext("2d");
  ctx.font = "20px Courier New";
  code = <% getCaptchastring(); %>;
  ctx.strokeText(code, 0, 15);
  document.getElementById("captcha").appendChild(canv);
  refillFields();
}
function refreshCaptcha()
{
  var username = document.getElementById("user").value;
  var password = document.getElementById("pass").value;
  sessionStorage.setItem("username", username);
  sessionStorage.setItem("password", password);
  sessionStorage.setItem("flag", '1');
  parent.location.reload();
}
function refillFields()
{
  var x = sessionStorage.getItem('flag');
  if (x!==null)
 x = Number(x);
  if (x==1)
  {
 var username = document.getElementById("user");
 var password = document.getElementById("pass");
 var u = sessionStorage.getItem('username');
 var p = sessionStorage.getItem('password');
 if (u!==null)
  username=username.setAttribute('value', u);
 if (p!==null)
  password=password.setAttribute('value',p);
 sessionStorage.clear();
  }
}
function setpass(obj)
{
 <% passwd2xmit(); %>
 obj.isclick = 1;
 postTableEncrypt(document.cmlogin.postSecurityFlag, document.cmlogin);
}
function mlhandle()
{
 postTableEncrypt(document.formML.postSecurityFlag, document.formML);
 document.formML.submit();
 parent.location.reload();
}
</SCRIPT>
</head>
<body onload="createCaptcha()">
<blockquote>
<form action=/boaform/admin/formLogin method=POST name="cmlogin">
<input type="hidden" name="challenge">
<TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
  <TBODY>
  <TR vAlign=top>
    <TD width="50%"><A><IMG height=78 src="LoginFiles/logo.jpg" width=78 useMap=#n1E6.$Body.0.1E8 border=0></A></TD>
  </TR>
  </TBODY>
</TABLE>
<CENTER>
  <TABLE cellSpacing=0 cellPadding=0 border=0>
    <TBODY>
      <TR vAlign=top>
        <TD width=350><BR>
          <TABLE cellSpacing=0 cellPadding=0 width="100%" border=0>
            <TBODY>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><IMG height=32 src="LoginFiles/locker.gif" width=32><BR><BR></DIV></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT color=#0000FF size=2><% multilang("813" "LANG_INPUT_USERNAME_AND_PASSWORD"); %></FONT><BR><BR></TD>
       </TR>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><FONT color=#0000FF size=2><% multilang("836" "LANG_USER"); %><% multilang("700" "LANG_NAME"); %>:</FONT></DIV></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT><INPUT maxLength=30 size=20 name=username id=user></FONT></TD>
              </TR>
              <TR vAlign=top>
                <TD vAlign=center width="29%"><DIV align=right><FONT color=#0000FF size=2><% multilang("67" "LANG_PASSWORD"); %>:</FONT></DIV></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT><INPUT type=password maxLength=30 size=20 name=password id=pass></FONT></TD>
    </TR>
     <TR vAlign=top>
    <TD vAlign=center width="29%"><FONT><div id="captcha" align=right></div></FONT></TD>
    <TD vAlign=center width="5%"></TD>
    <TD vAlign=center width="71%"><input type="text" placeholder="Captcha" name="captchaTextBox"/></FONT></TD>
    <TD vAlign=center width="71%"><input type="button" id="refreshcap" onclick="refreshCaptcha()" value="Refresh" style="right;"></FONT></TD>
       </TR>
              <TR vAlign=top>
                <TD vAlign=center width="29%"></TD>
                <TD vAlign=center width="5%"></TD>
                <TD vAlign=center width="71%"><FONT size=2></FONT><BR><INPUT type=submit value="<% multilang("814" "LANG_LOGIN"); %>" name=save onClick=setpass(this)></TD>
       </TR>
            </TBODY>
   </TABLE>
        </TD>
      </TR>
    </TBODY>
  </TABLE>
</CENTER>
<DIV align=center></DIV>
<input type="hidden" value="/admin/login.asp" name="submit-url">
<input type="hidden" name="postSecurityFlag" value="">
</form>
</blockquote>
<blockquote>
<form action=/boaform/admin/formLoginMultilang method=POST name="formML">
<CENTER><TABLE cellSpacing=0 cellPadding=0 border=0>
<tr><td>
 <% checkWrite("loginSelinit"); %>
 <input type="hidden" name="postSecurityFlag" value="">
</td></tr>
</TABLE></CENTER>
</form>
</blockquote>
</BODY>
</HTML>
