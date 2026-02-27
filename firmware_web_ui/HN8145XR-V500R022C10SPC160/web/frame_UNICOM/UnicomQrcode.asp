<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
    <meta http-equiv="Pragma" content="no-cache" />
    <title>qrcode</title>
    <script language="JavaScript" type="text/javascript">

        function WebGetQrcodeInfo(isLoidOk, isEnableRedirect, url) {
            this.isLoidOk = isLoidOk;
            this.isEnableRedirect = isEnableRedirect;
            this.url = url;
        }
        var qrcodeinfo = <% WEB_GetUnicomQrcodeInfo();%>;
        console.log(qrcodeinfo);

        function LoadFrame() {
            if ((qrcodeinfo[0].isEnableRedirect == 1) && (qrcodeinfo[0].url != '') && (qrcodeinfo[0].isLoidOk == 1)) {
                window.location = qrcodeinfo[0].url;
            }
        }

    </script>
    <style type="text/css">
    </style>
</head>

<body class="mainbody" onLoad="LoadFrame();" id="qrcodebody">
</body>

</html>