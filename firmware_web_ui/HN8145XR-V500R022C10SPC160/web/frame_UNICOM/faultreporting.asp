<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <title>陕西联通报障页面显示</title>
    <style>
        #main {
            position: absolute;
            background-color: white;
            width: 500px;
            height: 150px;
            border: 2px solid black;
        }
        #content {
            position: absolute;
            background-color: white;
        }

        .font {
            text-align: center;
            line-height: 30px;
            font-size: 22px;
            font-weight: 800;
            color: rgba(14, 109, 160, 0.522);
            margin-bottom: 8px;
        }
    </style>
    <script type="text/javascript">
        var operationsName = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.FaultReporting.OperationsName);%>';
        var operationsNumber = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.FaultReporting.OperationsNumber);%>';
        var territorialChinese = ['西安','咸阳','渭南','延安','宝鸡','榆林','铜川','汉中','安康','商洛'];
        var territorialfullSpelling = ['xian','xianyang','weinan','yanan','baoji','yulin','tongchuan','hanzhong','ankang','shangluo'];

        function getTerritorialName(operationsName){
            var nameIndex = territorialfullSpelling.indexOf(operationsName);
            if (nameIndex < 0) {
                return operationsName;
            }
            return territorialChinese[nameIndex]
        }
    </script>
<body>
    <div id="main">
        <div id="content">
            <div class="font">您的网络已中断，请致电：</div>
            <script type="text/javascript">
                var tip = getTerritorialName(operationsName) + '联通' + operationsNumber + '服务专线';
                document.write('<div class="font">' + tip + '</div>');
            </script>
            <div class="font">我们将竭诚为您服务！</div>
        </div>
    </div>
    <script type="text/javascript">
        function getPosition() {
            var windowScreen = document.documentElement;
            var main_div = document.getElementById("main");

            var main_left = (windowScreen.clientWidth - main_div.clientWidth) / 2 + "px";
            var main_top = (windowScreen.clientHeight - main_div.clientHeight) / 2 + "px";

            main_div.style.left = main_left;
            main_div.style.top = main_top;

            var content_div = document.getElementById("content");
            var content_left = (main_div.clientWidth - content_div.clientWidth) / 2 + "px";
            var content_top = (main_div.clientHeight - content_div.clientHeight) / 2 + "px";
            content_div.style.left = content_left;
            content_div.style.top = content_top;
        }
        window.onload = function () {
            getPosition()
        }
    </script>
</body>
</html>
</html>
