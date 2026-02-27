function CleanServiceListVoip()
{
    var ServiceList = document.getElementById("ServiceList");
    var Length = ServiceList.options.length;
	var ProductName = GetProductName();
	
	if ((ProductName != 'HG8045') && (ProductName != 'HG8010') && (ProductName != 'HG8040') && (ProductName != 'HG8045A') && (ProductName != 'HG8045H') && (ProductName != 'HG8045D') && (ProductName != 'HG8021H')
		 && (IsSupportVoice != '0'))
	{
		return true;
	}
	
    for (var i = Length; i >=0; i--)
    {
        try
        {
            var Child = ServiceList.options[i];
            if (Child == undefined)
            {
               continue;
            }
            
            if ((Child.value.toString().toUpperCase() == "VOIP" 
               || Child.value.toString().toUpperCase() == "TR069_VOIP" 
               || Child.value.toString().toUpperCase() == "VOIP_INTERNET"
               || Child.value.toString().toUpperCase() == "TR069_VOIP_INTERNET"
			   || Child.value.toString().toUpperCase() == "VOIP_IPTV" 
			   || Child.value.toString().toUpperCase() == "TR069_VOIP_IPTV")
			   && (selctIndex == -1))
            {
                ServiceList.remove(i);        
            }			
        }
        catch(ex)
        {
        }
    }
}

function RemoveAllFromSelectByKey(objSelect, objItemKey) 
{             
	for (var i = objSelect.options.length -1 ; i >= 0; i--) 
	{  
		if(objSelect.options[i].value.indexOf(objItemKey) >= 0 )  
		{ 
            objSelect.options[i]=null;            
        }     
    }
}

function RemoveItemFromSelect(objSelect, objItemValue) 
{             
    for (var i = 0; i < objSelect.options.length; i++) 
	{  
	
		if(objSelect.options[i].value == objItemValue) 
		{        
            objSelect.options[i]=null;         
            break;        
        }     
    }
}

function ClearIPTVAndOtherService()
{
	if(0== ROSTelecomFeature)
	{
		return ;
	}
	var svrlist = getElementById("ServiceList");
	RemoveAllFromSelectByKey(svrlist,Languages['IPTV']);
	RemoveAllFromSelectByKey(svrlist,Languages['OTHER']);
}
function innerControlsvrlist()
{
	var svrlist = getElementById("ServiceList");
	var Wan = GetCurrentWan();
	
	svrlist.options.length = 0;

	svrlist.options.add(new Option(Languages['TR069'],Languages['TR069']));
	svrlist.options.add(new Option(Languages['INTERNET'],Languages['INTERNET']));
	svrlist.options.add(new Option(Languages['TR069_INTERNET'],Languages['TR069_INTERNET']));
	if('E8C' == CurrentBin.toUpperCase()|| CUVoiceFeature == "1")
	{
		svrlist.options.add(new Option("VOICE",Languages['VOIP']));
		svrlist.options.add(new Option("TR069_VOICE",Languages['TR069_VOIP']));
		svrlist.options.add(new Option("VOICE_INTERNET",Languages['VOIP_INTERNET']));
		svrlist.options.add(new Option("TR069_VOICE_INTERNET",Languages['TR069_VOIP_INTERNET']));
	}
	else
	{
		svrlist.options.add(new Option(Languages['VOIP'],Languages['VOIP']));
		svrlist.options.add(new Option(Languages['TR069_VOIP'],Languages['TR069_VOIP']));
		svrlist.options.add(new Option(Languages['VOIP_INTERNET'],Languages['VOIP_INTERNET']));
		svrlist.options.add(new Option(Languages['TR069_VOIP_INTERNET'],Languages['TR069_VOIP_INTERNET']));
		svrlist.options.add(new Option(Languages['IPTV_INTERNET'],Languages['IPTV_INTERNET']));
		svrlist.options.add(new Option(Languages['VOIP_IPTV_INTERNET'],Languages['VOIP_IPTV_INTERNET']));
		svrlist.options.add(new Option(Languages['TR069_IPTV_INTERNET'],Languages['TR069_IPTV_INTERNET']));
		svrlist.options.add(new Option(Languages['TR069_VOIP_IPTV_INTERNET'],Languages['TR069_VOIP_IPTV_INTERNET']));
	}
	if(!IsE8cFrame())
	{
		svrlist.options.add(new Option(Languages['IPTV'],Languages['IPTV']));
	}
	svrlist.options.add(new Option(Languages['OTHER'],Languages['OTHER']));
	
	svrlist.value = Languages['INTERNET'] ;
	
	if((getValue('WanMode').toString().toUpperCase().indexOf("ROUTED") >= 0))
	{
		if(("TELMEXACCESS" == CfgModeWord.toUpperCase()) &&(EditFlag.toUpperCase() == "ADD"))
		{
			svrlist.value = Languages['TR069_INTERNET'];
			Wan.ServiceList = "TR069_INTERNET";
		}
		if(("TELMEXRESALE" == CfgModeWord.toUpperCase()) &&(EditFlag.toUpperCase() == "ADD"))
		{
			svrlist.value = Languages['TR069_VOIP_INTERNET'];
			Wan.ServiceList = "TR069_VOIP_INTERNET";
		}
		if((("TELMEXRESALE" == CfgModeWord.toUpperCase()) || ("TELMEXACCESS" == CfgModeWord.toUpperCase()) ) &&(EditFlag.toUpperCase() == "EDIT"))
		{
			if( -1 != selctIndex)
			{
				Wan.ServiceList = GetWanList()[selctIndex].ServiceList;
			}
		}
	}
	
	if(getValue('WanMode').toString().toUpperCase().indexOf("BRIDGED") >= 0)
	{
		svrlist.options.length = 0;
		svrlist.options.add(new Option(Languages['INTERNET'],Languages['INTERNET']));
		if(!IsE8cFrame())
		{
			svrlist.options.add(new Option(Languages['IPTV'],Languages['IPTV']));
		}
		svrlist.options.add(new Option(Languages['OTHER'],Languages['OTHER']));
		
		var PriorityPolicy = (Wan.EnableVlan == "1") ? Wan.PriorityPolicy:"Specified";
		if(PriorityPolicy.toUpperCase() == "DSCPTOPBIT")
	    {
			setSelect('PriorityPolicy', 'Specified');
		}
		
		switch(GetCurrentWan().ServiceList.toString().toUpperCase()) 
		{
			case Languages['INTERNET']:
			case Languages['OTHER']:
			case Languages['IPTV']:
				svrlist.value = GetCurrentWan().ServiceList.toString().toUpperCase();
				break;
			default:
				if ((1 == MngtShct || CUVoiceFeature == "1") && (EditFlag.toUpperCase() != "ADD"))
				{
					var servalue = GetCurrentWan().ServiceList.toString().toUpperCase();
					if(servalue == Languages['TR069_VOIP'])
					{
						svrlist.options.add(new Option("TR069_VOICE","TR069_VOIP"));
						setSelect("ServiceList","TR069_VOIP");
					}
					else if(servalue == Languages['VOIP'])
					{
						svrlist.options.add(new Option("VOICE","VOIP"));
						setSelect("ServiceList","VOIP");
					}
					else if(servalue == Languages['VOIP_INTERNET'])
					{
						svrlist.options.add(new Option("VOICE_INTERNET","VOIP_INTERNET"));
						setSelect("ServiceList","VOIP_INTERNET");
					}
					else if(servalue == Languages['TR069_VOIP_INTERNET'])
					{
						svrlist.options.add(new Option("TR069_VOICE_INTERNET","TR069_VOIP_INTERNET"));
						setSelect("ServiceList","TR069_VOIP_INTERNET");
					}
					else if(servalue == Languages['VOIP_IPTV'])
					{
						svrlist.options.add(new Option("VOICE_IPTV","VOIP_IPTV"));
						setSelect("ServiceList","VOIP_IPTV");
					}
					else if(servalue == Languages['TR069_VOIP_IPTV'])
					{
						svrlist.options.add(new Option("TR069_VOICE_IPTV","TR069_VOIP_IPTV"));
						setSelect("ServiceList","TR069_VOIP_IPTV");
					}
					else
					{
                        svrlist.options.add(new Option(GetCurrentWan().ServiceList.toString().toUpperCase(), GetCurrentWan().ServiceList.toString().toUpperCase()));
                        svrlist.value = GetCurrentWan().ServiceList.toString().toUpperCase();				
					}
				}
				else
				{
					if("TELMEXACCESS" == CfgModeWord.toUpperCase())
					{
						svrlist.value = Languages['INTERNET'];
					}
					else if( "TELMEXRESALE" == CfgModeWord.toUpperCase())
					{
						svrlist.value = Languages['INTERNET'];
					}
					else
					{
						if((EditFlag.toUpperCase() == "ADD") && ((Wan.ServiceList == 'INTERNET') || (Wan.ServiceList == 'IPTV') || (Wan.ServiceList == 'OTHER'))
							|| (EditFlag.toUpperCase() != "ADD"))
						{
							svrlist.options.add(new Option(GetCurrentWan().ServiceList.toString().toUpperCase(), GetCurrentWan().ServiceList.toString().toUpperCase()));
							svrlist.value = GetCurrentWan().ServiceList.toString().toUpperCase();
						}
					}
				}
				break;
		}
		
	    	if( SingtelModeEX == 1)
		{
			RemoveItemFromSelect(svrlist , Languages['IPTV']);
		}
		return ;
	}

	if ((bin4board_nonvoice() == true)&&(selctIndex == -1))
	{
		RemoveAllFromSelectByKey(svrlist , Languages['VOIP']);
	}

	if(((bin5board() == true) || ("1" == FtBin5Enhanced)) && (EditFlag.toUpperCase() == "ADD")) 
	{
		RemoveItemFromSelect(svrlist , Languages['INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['TR069_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['VOIP_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['TR069_VOIP_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['IPTV']);
		RemoveItemFromSelect(svrlist , Languages['OTHER']);
		RemoveItemFromSelect(svrlist , Languages['IPTV_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['VOIP_IPTV_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['TR069_IPTV_INTERNET']);
		RemoveItemFromSelect(svrlist , Languages['TR069_VOIP_IPTV_INTERNET']);

		
		if(Wan.ServiceList.toString().toUpperCase()=='INTERNET')
		{
		    svrlist.value=Languages['TR069'];
   			Wan.ServiceList = "TR069";
		}
		else
		{
		    svrlist.value=Languages[Wan.ServiceList.toString().toUpperCase()];
		}
		
		CleanServiceListVoip();
		return;
	}
	
	if(!IsE8cFrame())
	{
		if(CUVoiceFeature == "1")
		{
			svrlist.options.add(new Option("VOICE_IPTV","VOIP_IPTV"));
			svrlist.options.add(new Option("TR069_IPTV","TR069_IPTV"));
			svrlist.options.add(new Option("TR069_VOICE_IPTV","TR069_VOIP_IPTV"));
		}
		else
		{
			svrlist.options.add(new Option(Languages['VOIP_IPTV'],Languages['VOIP_IPTV']));
			svrlist.options.add(new Option(Languages['TR069_IPTV'],Languages['TR069_IPTV']));
			svrlist.options.add(new Option(Languages['TR069_VOIP_IPTV'],Languages['TR069_VOIP_IPTV']));
		}
		svrlist.value = Wan.ServiceList.toString().toUpperCase();
		
		CleanServiceListVoip();

		if( SingtelModeEX == 1)
		{
		    RemoveAllFromSelectByKey(svrlist , Languages['VOIP']);
	        RemoveAllFromSelectByKey(svrlist , Languages['IPTV']);
		}
		return;
	}
	else
	{   
	    svrlist.value = Wan.ServiceList.toString().toUpperCase();
	    CleanServiceListVoip();
	    return;
	}
}
function Controlsvrlist()
{
	innerControlsvrlist();
	ClearIPTVAndOtherService();
}