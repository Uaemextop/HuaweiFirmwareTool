<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<meta http-equiv="X-UA-Compatible" content="IE=edge;chrome=1">
<meta http-equiv="Pragma" content="no-cache" />
<script src="/resource/common/<%HW_WEB_CleanCache_Resource(jquery.min.js);%>" type="text/javascript"></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(util.js);%>"></script>
<link rel="stylesheet" href="../../../resource/common/<%HW_WEB_CleanCache_Resource(style.css);%>" type="text/css"/>
<link rel="stylesheet"  href='../../../Cuscss/<%HW_WEB_GetCusSource(frame.css);%>' type='text/css'>
<script language="JavaScript" src='../../../Cusjs/<%HW_WEB_GetCusSource(InitFormCus.js);%>'></script>
<script language="JavaScript" src="../../../resource/common/<%HW_WEB_CleanCache_Resource(InitForm.asp);%>"></script>
<script language="JavaScript" src="../../../resource/<%HW_WEB_Resource(bbspdes.html);%>"></script>
<style type='text/css'>

</style>
</head>
<script>

var adaptAppleDNSEnable = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_FeatureList.BBSPCustomization.AdaptAppleDnsObj.Enable);%>'; 

function LoadFrame(){
    document.getElementsByClassName("divsummaryicon")[0].style.display = "none";
    setCheck('AppleDNSEnable',adaptAppleDNSEnable);
}

function changeEnable() {
    setDisable('AppleDNSEnable', 1);
    var AppleDNSEnable = getCheckVal('AppleDNSEnable');
    var url = 'set.cgi?x=InternetGatewayDevice.X_HW_FeatureList.BBSPCustomization.AdaptAppleDnsObj'
    var Form = new webSubmitForm();
    var RequestFile = 'html/bbsp/adaptApple/adaptAppleDNS.asp';
    url = url + '&RequestFile=' + RequestFile;
    Form.addParameter('x.Enable', AppleDNSEnable);
    Form.addParameter('x.X_HW_Token', getValue('onttoken'));
    Form.setAction(url);
    Form.submit();
    
}

</script>

<body onLoad="LoadFrame();" class="mainbody">
    <script>
        var adaptApple_header = adaptapple_language['adaptAppleDns'];
        var adaptAppleSummaryArray = new Array(new stSummaryInfo("img","", ""),
                                               new stSummaryInfo("text", GetDescFormArrayById(adaptapple_language, "adaptAppleDns_title") + "<br>"),
                                               null);
    
        HWCreatePageHeadInfo("adaptAppleTable", adaptApple_header, adaptAppleSummaryArray, true);
    </script>
    <div class="title_spread"></div>
    <form id="adaptApple" name="FreeArpForm" style="display:block;">
        <table border="0" cellpadding="0" cellspacing="1"  width="100%" class="tabal_noborder_bg">
            <input type="hidden" name="onttoken" id="hwonttoken" value="<%HW_WEB_GetToken();%>">
            <li id="AppleDNSEnable" RealType="CheckBox" DescRef="adaptAppleDns" RemarkRef="Empty" ErrorMsgRef="Empty" Require="FALSE" BindField="x.enable" InitValue="Empty" InitValue="0"   ClickFuncApp="onclick=changeEnable"/>
        </table>
        <script>
            var TableClass = new stTableClass("width_per30", "width_per70", "ltr");
            var FreeArpConfigFormList = new Array();
            FreeArpConfigFormList = HWGetLiIdListByForm("FreeArpForm", null);
            HWParsePageControlByID("FreeArpForm", TableClass, adaptapple_language, null);
        </script>
        <div class="func_spread"></div>
    </form>
</body>
</html>
