<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1"><!-IE7 mode->
<meta http-equiv="Pragma" content="no-cache" />
<title></title>
<link href="/Cuscss/<%HW_WEB_GetCusSource(frame.css);%>"  media="all" rel="stylesheet" />
<script type="text/javascript" src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<script id="langResource" language="JavaScript" src="/frameaspdes/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<script language="JavaScript" src='../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script type="text/javascript" src="/resource/<%HW_WEB_Resource(ssmpdes.js);%>"></script>
<style type="text/css">
#main_wrapper {
    width:100%;
    margin:0px;
    padding:0px;
    border-width:0px;
    text-align:center;
    vertical-align:top;
    background-image:url();
    background-color:rgb(218,41,28);
}
</style>
<script language="JavaScript" type="text/javascript">

var CfgMode ='<%HW_WEB_GetCfgMode();%>';
var ProductName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.DeviceInfo.ModelName);%>';

var langDescList = new Array();
langDescList["chinese"] = "简体中文"; //or just '中文'?
langDescList["english"] = "English";
langDescList["japanese"] = "日本語";
langDescList["arabic"] = "العربية";
langDescList["portuguese"] = "Português";
langDescList["spanish"] = "Español";
langDescList["turkish"] = "Türkçe";
langDescList["brasil"] = "Brasil";
langDescList["german"] = "German";

function Confirm()
{
    window.location="userguideframe_claro.asp"
}
</script>
</head>
<body">
    <div id="main_wrapper">
        <div id="guidejump" class="guide" onclick="gotoIndex()">
            <script>document.write(CfgguideLgeDes["s4011"])</script>
        </div>
        <div id="confirmarea">
            <div id="brandlog_claro"></div>
            <script>
                document.write('<div id="ProductName">' + ProductName + '</div>');
            </script>
            <div id="guideconfirm">
                <span class="guidetitle" BindText="guidepage001"></span>
            </div>
            <div id="guideinfo">
                <span class="guidetext" BindText="guidepage002"></span>
            </div>
            <div class="contenbox_guide">
                <input type="button" class="whitebuttonBlueBgcss confirmbutton" onclick="Confirm();" value="advance" bindtext="guidepage003">
            </div>
        </div>
        <div id="greenline"></div>
        <div id="copyright">
            <div id="copyrightspace"></div>
            <div id="copyrightlog"></div>
            <div id="copyrighttext"><span id="footer" BindText="frame015a"></span></div>
        </div>
    </div>
    <script>
        ParseBindTextByTagName(framedesinfo, "span", 1);
        ParseBindTextByTagName(framedesinfo, "input", 2);
    </script>
</body>
</html>
