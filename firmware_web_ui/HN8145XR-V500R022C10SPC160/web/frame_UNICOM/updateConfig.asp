<html>

<head>
  <title>亲！智能网关有新版本</title>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
  <link href="Cuscss/<%HW_WEB_CleanCache_Resource(login.css);%>" media="all" rel="stylesheet" />
  <link href="Cuscss/<%HW_WEB_CleanCache_Resource(frame.css);%>" type='text/css' rel="stylesheet">
  <script language="JavaScript" src="/../resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
  <script language="JavaScript" src="/resource/common/<%HW_WEB_CleanCache_Resource(safelogin.js);%>"></script>
  <script language="JavaScript" type="text/javascript">


    function setdisableall() {
      document.getElementById('btnApply1').disabled = true;
      document.getElementById('btnApply2').disabled = true;
      document.getElementById('btnApply3').disabled = true;
    }

    function submitbtn1() {
      var Form = new webSubmitForm();
      Form.setAction('agreePopUpgrade.cgi?&RequestFile=updateNote.asp');
      Form.addParameter('x.X_HW_Token', getAuthToken());
      setdisableall();
      Form.submit();
    }

    function submitbtn2() {
      var Form = new webSubmitForm();
      Form.setAction('refusePopUpgrade.cgi?&RequestFile=updateNote.asp');
      Form.addParameter('x.X_HW_Token', getAuthToken());	
      setdisableall();
      Form.submit();
    }
    function submitbtn3() {
      var Form = new webSubmitForm();
      Form.setAction('remindPopUpgrade.cgi?&RequestFile=updateNote.asp');
      Form.addParameter('x.X_HW_Token', getAuthToken());
      setdisableall();
      Form.submit();
    }

  </script>
</head>

<body>

  <div>
    <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
    <button id="btnApply1" name="btnApply1" type="button" class="submit" onClick="submitbtn1();">升级</script></button>
    <button name="btnApply2" id="btnApply2" class="submit" type="button" onClick="submitbtn2();">不升级</button>
    <button name="btnApply3" id="btnApply3" class="submit" type="button" onClick="submitbtn3();">暂不升级</button>
  </div>



</body>

</html>