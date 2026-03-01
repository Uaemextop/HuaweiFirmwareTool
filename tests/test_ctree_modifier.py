"""Tests for tools/ctree_modifier.py"""

import os
import sys
import pytest

# Add tools directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))
import ctree_modifier


SAMPLE_CONFIG = '''<InternetGatewayDevice DBEncrypt="1">
<LANDevice NumberOfInstances="1">
<LANDeviceInstance InstanceID="1">
<LANHostConfigManagement DHCPServerEnable="1" X_HW_TftpServerEnable="0"/>
</LANDeviceInstance>
</LANDevice>
<X_HW_IPv6Config DomainName="">
<PrefixInformationInstance InstanceID="1" Mode="WANDelegated" Prefix="" PreferredLifeTime="3600" ValidLifeTime="7200" DelegatedWanConnection=""/>
<PrefixInformation NumberOfInstances="1">
<PrefixInformationInstance InstanceID="1" Mode="WANDelegated" Prefix="" PreferredLifeTime="3600" ValidLifeTime="7200" DelegatedWanConnection=""/>
</PrefixInformation>
</X_HW_IPv6Config>
<X_HW_LogCfg SrvAddr="0xC0A86401" Port="6543" DbgSwitch="0" RtoSwitch="0" MidFlag="2" LogTypeMask="2"/>
<UserInterface>
<X_HW_CLITelnetAccess Access="0" TelnetPort="23"/>
</UserInterface>
<ManagementServer EnableCWMP="1" URL="http://acs.example.com" Username="admin" Password="pass" PeriodicInformEnable="1" PeriodicInformInterval="43200" STUNEnable="1" ConnectionRequestUsername="user" ConnectionRequestPassword="pw" UpgradesManaged="1" X_HW_EnableCertificate="1"/>
<DeviceInfo X_HW_UpPortMode="4">
<X_HW_Syslog Enable="0" Level="3"/>
<X_HW_SyslogConfig LogServerEnable="0" Severity="" ServerAddress="" ServerPort="514"/>
<X_HW_Reportlog Enable="0" ReportLogType="1"/>
</DeviceInfo>
<X_HW_ServiceManage FtpEnable="0" FtpPort="21"/>
<X_HW_SFTP>
<X_HW_SFTP_ServerInfo SftpEnable="0" SftpPort="8022" SftpLANEnable="0" SftpWANEnable="0"/>
</X_HW_SFTP>
<X_HW_APMPolicy EnablePowerSavingMode="1"/>
<X_HW_PSIXmlReset ResetFlag="1"/>
<X_HW_ProductInfo originalVersion="V300R020" currentVersion="V300R020" customInfo="TELMEX" customInfoDetail="telmex"/>
<X_HW_iaccess Enable="1" ReportEnable="1" SecPlatEnable="2"/>
<X_HW_AppRemoteManage MgtURL="http://manage.example.com"/>
<X_HW_Audit Enable="1"/>
<X_HW_AutoReboot Enable="1"/>
<ExtDeviceInfo X_HW_LedSwitch="0"/>
<X_HW_CheckSafety Enable="1"/>
</InternetGatewayDevice>'''


class TestFixXmlErrors:
    def test_remove_duplicate_prefix(self):
        xml, changes = ctree_modifier.fix_xml_errors(SAMPLE_CONFIG)
        assert len(changes) > 0
        # Should only have one PrefixInformationInstance (inside PrefixInformation)
        count = xml.count('<PrefixInformationInstance ')
        assert count == 1, f"Expected 1 PrefixInformationInstance, got {count}"


class TestSetAttribute:
    def test_set_existing_attribute(self):
        xml, ok = ctree_modifier.set_attribute(
            SAMPLE_CONFIG, "ManagementServer", "EnableCWMP", "0"
        )
        assert ok
        assert 'EnableCWMP="0"' in xml

    def test_nonexistent_element(self):
        xml, ok = ctree_modifier.set_attribute(
            SAMPLE_CONFIG, "NonExistentElement", "Attr", "1"
        )
        assert not ok


class TestEnableLogging:
    def test_syslog_enabled(self):
        xml, changes = ctree_modifier.enable_logging(SAMPLE_CONFIG)
        assert 'X_HW_Syslog Enable="1"' in xml
        assert 'Level="7"' in xml

    def test_debug_switch_on(self):
        xml, changes = ctree_modifier.enable_logging(SAMPLE_CONFIG)
        assert 'DbgSwitch="1"' in xml
        assert 'RtoSwitch="1"' in xml

    def test_log_type_mask_all(self):
        xml, changes = ctree_modifier.enable_logging(SAMPLE_CONFIG)
        assert 'LogTypeMask="255"' in xml

    def test_syslog_config_enabled(self):
        xml, changes = ctree_modifier.enable_logging(SAMPLE_CONFIG)
        assert 'LogServerEnable="1"' in xml
        assert 'Severity="7"' in xml

    def test_report_log_enabled(self):
        xml, changes = ctree_modifier.enable_logging(SAMPLE_CONFIG)
        assert 'X_HW_Reportlog Enable="1"' in xml


class TestEnableServices:
    def test_telnet_enabled(self):
        xml, changes = ctree_modifier.enable_services(SAMPLE_CONFIG)
        assert 'X_HW_CLITelnetAccess Access="1"' in xml

    def test_ssh_added(self):
        xml, changes = ctree_modifier.enable_services(SAMPLE_CONFIG)
        assert 'X_HW_CLISSHAccess Access="1"' in xml

    def test_ftp_enabled(self):
        xml, changes = ctree_modifier.enable_services(SAMPLE_CONFIG)
        assert 'FtpEnable="1"' in xml

    def test_sftp_enabled(self):
        xml, changes = ctree_modifier.enable_services(SAMPLE_CONFIG)
        assert 'SftpEnable="1"' in xml
        assert 'SftpLANEnable="1"' in xml
        assert 'SftpWANEnable="1"' in xml

    def test_tftp_enabled(self):
        xml, changes = ctree_modifier.enable_services(SAMPLE_CONFIG)
        assert 'X_HW_TftpServerEnable="1"' in xml


class TestDisableTr069:
    def test_cwmp_disabled(self):
        xml, changes = ctree_modifier.disable_tr069_cwmp(SAMPLE_CONFIG)
        assert 'EnableCWMP="0"' in xml

    def test_periodic_inform_disabled(self):
        xml, changes = ctree_modifier.disable_tr069_cwmp(SAMPLE_CONFIG)
        assert 'PeriodicInformEnable="0"' in xml

    def test_stun_disabled(self):
        xml, changes = ctree_modifier.disable_tr069_cwmp(SAMPLE_CONFIG)
        assert 'STUNEnable="0"' in xml

    def test_credentials_cleared(self):
        xml, changes = ctree_modifier.disable_tr069_cwmp(SAMPLE_CONFIG)
        assert 'Username=""' in xml
        assert 'Password=""' in xml

    def test_iaccess_disabled(self):
        xml, changes = ctree_modifier.disable_tr069_cwmp(SAMPLE_CONFIG)
        assert 'X_HW_iaccess Enable="0"' in xml
        assert 'ReportEnable="0"' in xml
        assert 'SecPlatEnable="0"' in xml


class TestEnableDowngrade:
    def test_reset_flag_off(self):
        xml, changes = ctree_modifier.enable_downgrade(SAMPLE_CONFIG)
        assert 'ResetFlag="0"' in xml

    def test_check_safety_off(self):
        xml, changes = ctree_modifier.enable_downgrade(SAMPLE_CONFIG)
        assert 'X_HW_CheckSafety Enable="0"' in xml

    def test_upgrades_managed_off(self):
        xml, changes = ctree_modifier.enable_downgrade(SAMPLE_CONFIG)
        assert 'UpgradesManaged="0"' in xml


class TestSetVersionInfo:
    def test_version_set(self):
        xml, changes = ctree_modifier.set_version_info(SAMPLE_CONFIG)
        assert 'currentVersion="V500R020"' in xml
        assert 'customInfo="COMMON"' in xml


class TestAddFlashConfig:
    def test_power_saving_off(self):
        xml, changes = ctree_modifier.add_flash_config(SAMPLE_CONFIG)
        assert 'EnablePowerSavingMode="0"' in xml

    def test_auto_reboot_off(self):
        xml, changes = ctree_modifier.add_flash_config(SAMPLE_CONFIG)
        assert 'X_HW_AutoReboot Enable="0"' in xml

    def test_led_on(self):
        xml, changes = ctree_modifier.add_flash_config(SAMPLE_CONFIG)
        assert 'X_HW_LedSwitch="1"' in xml


class TestModifyConfig:
    def test_all_changes_applied(self):
        xml, changes = ctree_modifier.modify_config(SAMPLE_CONFIG)
        assert len(changes) > 30

    def test_output_is_valid(self):
        xml, changes = ctree_modifier.modify_config(SAMPLE_CONFIG)
        assert xml.startswith('<InternetGatewayDevice')
        assert xml.strip().endswith('</InternetGatewayDevice>')
