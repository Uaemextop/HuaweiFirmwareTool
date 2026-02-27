<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
    <meta http-equiv=Content-Type content="text/html; charset=UTF-8">
    <style>
        #tophead {
            position: absolute;
            top: 60px;
            left: 680px;
            font-weight: bolder;
        }

        #note1 {
            margin-top: 25px;
            margin-left: 50px;
            width: 700px;
            text-indent: 0px;
            font-size: 22px;
            color: #000000;
            font-weight: bolder;
        }

        #note2 {
            margin-top: 0px;
            margin-left: 50px;
            width: 700px;
            text-indent: 40px;
            font-size: 22px;
            color: #000000;
            line-height: 2em;
        }

        #note3 {
            margin-top: 10px;
            margin-left: 50px;
            width: 700px;
            text-indent: 0px;
            font-size: 17px;
            color: #000000;
            line-height: 2em;
        }

        #note4 {
            margin-top: 20px;
            margin-left: 50px;
            width: 700px;
            text-indent: 0px;
            font-size: 22px;
            color: #000000;
            line-height: 2em;
        }

        #note5 {
            margin-top: -25px;
            margin-left: 520px;
            font-size: 20px;
            color: #000000;
            font-weight: bolder;
        }

        #qrcodeId {
            position: relative;
            margin-top: -150px;
            margin-left: 520px;
        }

        #triangle {
            border-style: solid;
            border-width: 0px 15px 15px 15px;
            border-color: transparent transparent black transparent;
            width: 0px;
            height: 0px;
        }

        #kfImg {
            width: 30%;
            margin-top: -220px;
            margin-left: 590px;
        }
    </style>
    <script language="JavaScript" src="/../../resource/common/<%HW_WEB_CleanCache_Resource(ahcode.js);%>"></script>
    <script>
        var completeURL = 'https://img.client.10010.com/kuandaizhuanqu/index.html';
        var errorCodeDic = {
            "9000101": "OLT注册失败",
            "9000102": "OLT注册超时", 
            "9000103": "PPPOE拨号认证失败", 
            "9000104": "PPPOE拨号认证超时", 
            "9000201": "PON LOS", 
            "9000202": "ONU长发光"
        };

        var content = '<%WEB_GetQRCode();%>';
        var arr = content.split('&');

        var pppoeID = arr[0].split("=")[1];
        var errorCode = arr[1].split("=")[1];
        var errName = errorCodeDic[errorCode];

        function ewcodeUrl() {
            window.location.href = completeURL;
        }

        function initqrcode() {
            var options = {
                text: "",
                width: 120,
                height: 120,
                id: "qrcodeId",
                className: "qrcodeclass",
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: wabQR.CorrectLevel.Q,
                logoSrc: '',
                logoRate: 0.33
            }
            options.text = completeURL;
            var obj = document.getElementById("qrcodeImage");
            new wabQR(obj, options);

            if ("ActiveXObject" in window || window.ActiveXObject) {
                document.getElementById("qrcodeTable").style.height = "605px";
                document.getElementById("note5").style.marginTop = "10px";
            }

            if ((navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|wOSBrowser|BrowserNG|WebOS)/i))) {
                var curInnerWidth = window.innerWidth < 1311? 1311 : window.innerWidth;
                var proportion = curInnerWidth / 440;
                document.getElementById("qrcodeTable").style = "width: 100%;height: 100%;background-color: #F1C15D;";
                document.getElementById("triangle").style.display = "block";
                document.getElementById("logImage").style = "width: 25%;margin: 5% 0 9% 8%;";
                document.getElementById("tophead").style = "left: 9.8%;margin-top: 28%;font-size: " + 22 * proportion + "px;";
                document.getElementById("note1").style = "font-weight: normal;font-size: " + 14 * proportion + "px;margin: 20% 0 0 9.8%;letter-spacing: 4px;line-height: 2em;";
                document.getElementById("note2").style = "width: 81%;font-weight: normal;font-size: " + 14 * proportion + "px;margin: 0% 0 0 9.8%;letter-spacing: 4px;line-height: 2em;text-indent: 2em;"
                document.getElementById("note3").innerHTML = "请先关闭手机WIFI，再通过手机扫描二维码或点击二维码进行自助报障。如无法扫描二维码，请拨打116114报障，感谢您的配合。";
                document.getElementById("note3").style = "width: 60%;font-weight: normal;font-size: " + 12 * proportion + "px;margin: 50% 0 0 9.8%;text-indent: 2em;";
                document.getElementById("note4").style = "width: 50%;font-weight: normal;font-size: " + 13 * proportion + "px;margin: -75% 0 0 45%;";
                document.getElementById("qrcodeId").style = "width: 30%;margin: -32% 25% 0px 9.8%;";
                document.getElementById("triangle").style = "margin: 0 0 0 22.5%"
                document.getElementById("note5").style = "border-radius: 10px;background:#000000; color:#F1C15D; text-align: center;width: 50%;font-weight: normal;font-size: " + 14 * proportion + "px;margin: 1% 0 0 9.8%;";
                document.getElementById("kfImg").style = "width: 40%;margin: 0% 0% 0 58%;";
                document.getElementById("foot").style = "font-size: " + 16 * proportion + "px; margin: -5% 2% 0;padding-bottom: 5%;";
                if (document.getElementById("note4").clientHeight < 250) {
                    document.getElementById("hintDiv").style.display = "block";
                } else if (document.getElementById("note4").clientHeight > 310) {
                    document.getElementById("qrcodeId").style = "width: 30%;margin: -34% 25% 0px 9.8%;";
                    document.getElementById("triangle").style = "margin: -2% 0 0 22.5%";
                }
            }
        }
    </script>
</head>

<body onload="initqrcode();">
    <div id="qrcodeTable" style="margin-left: 453px;width: 850px;height: 575px;background-color: #F1C15D;">
        <div>
            <div id="tophead" class="topTitle" style="font-size: 40px;">中国联通宽带自助报障系统</div>
            <img id="logImage" src="/images/cu_logo.gif" alt=""
                style="width: 17%;margin-top: 30px;margin-left: 50px;" />
        </div>
        <div id="note1">尊敬的联通用户：</div>
        <div id="note2">很抱歉，联通公司检测到您的家庭网络出现连接问题，请按照下面的方法步骤操作，我们将及时为您修复。</div>
        <div id="note3">请先关闭手机WIFI，再通过手机扫描二维码或点击二维码进行自助报障。<br />如无法扫描二维码，请拨打116114报障，感谢您的配合。</div>
        <div id="note4">
            <div id="accountID">宽带账号：</div>
            <div id="bandAppearance">宽带现象：</div>
            <div id="errorCode">故障代码：</div>
            <div id="hintDiv" style="display: none;"><br /></div>
        </div>
        <div id="qrcodeImage" onclick="ewcodeUrl()"></div>
        <div id="triangle" style="display: none;"></div>
        <div id="note5">有问题请扫我</div>
        <img id="kfImg" src="/images/animated.gif" alt="" />
        <div id="foot" style="font-size: 20px;margin-left: 50px;margin-top: 0px"></div>
    </div>
</body>

<script>
    document.getElementById("accountID").innerHTML += pppoeID;
    document.getElementById("bandAppearance").innerHTML += errName;
    document.getElementById("errorCode").innerHTML += errorCode;
</script>

</html>
