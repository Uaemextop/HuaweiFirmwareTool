"""Tests for ctree_modifier module."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from ctree_modifier import (
    disable_cwmp,
    enable_ftp,
    enable_ftp_service,
    enable_ssh,
    enable_telnet,
    list_acl_services,
    list_cli_users,
    set_cli_user_group,
    set_web_user_level,
    unlock_all,
)

# Minimal hw_ctree.xml fragment for testing
SAMPLE_XML = """\
<InternetGatewayDevice>
<AclServices HTTPLanEnable="1" HTTPWanEnable="0" FTPLanEnable="0" \
FTPWanEnable="0" TELNETLanEnable="1" TELNETWanEnable="0" \
SSHLanEnable="0" SSHWanEnable="0" HTTPPORT="80" FTPPORT="21" \
TELNETPORT="23" SSHPORT="22"/>
<UserInterface>
<X_HW_CLIUserInfo NumberOfInstances="1">
<X_HW_CLIUserInfoInstance InstanceID="1" Username="root" \
Userpassword="hash" UserGroup="" ModifyPWDFlag="0" EncryptMode="2"/>
</X_HW_CLIUserInfo>
<X_HW_WebUserInfo NumberOfInstances="2">
<X_HW_WebUserInfoInstance InstanceID="1" UserName="root" \
Password="hash" UserLevel="1" Enable="1" ModifyPasswordFlag="0"/>
<X_HW_WebUserInfoInstance InstanceID="2" UserName="telecomadmin" \
Password="hash" UserLevel="0" Enable="1" ModifyPasswordFlag="0"/>
</X_HW_WebUserInfo>
</UserInterface>
<ManagementServer EnableCWMP="1" URL="http://acs.isp.com" Username="" Password=""/>
<X_HW_ServiceManage FtpEnable="0" FtpPort="21"/>
</InternetGatewayDevice>
"""


class TestSetCliUserGroup:
    def test_set_usergroup(self):
        result, changed = set_cli_user_group(SAMPLE_XML, "root", "4294967295")
        assert changed
        assert 'UserGroup="4294967295"' in result

    def test_set_usergroup_nonexistent_user(self):
        result, changed = set_cli_user_group(SAMPLE_XML, "nobody", "123")
        assert not changed
        assert result == SAMPLE_XML

    def test_empty_to_full(self):
        result, _ = set_cli_user_group(SAMPLE_XML, "root", "4294967295")
        assert 'UserGroup=""' not in result
        assert 'UserGroup="4294967295"' in result


class TestSetWebUserLevel:
    def test_elevate_root_to_admin(self):
        result, changed = set_web_user_level(SAMPLE_XML, "root", "0")
        assert changed
        assert 'UserName="root"' in result
        # root should have level 0
        import re
        m = re.search(
            r'UserName="root"[^>]*UserLevel="([^"]*)"', result
        )
        assert m and m.group(1) == "0"

    def test_telecomadmin_unchanged(self):
        result, _ = set_web_user_level(SAMPLE_XML, "root", "0")
        import re
        m = re.search(
            r'UserName="telecomadmin"[^>]*UserLevel="([^"]*)"', result
        )
        assert m and m.group(1) == "0"  # already admin


class TestAclServices:
    def test_enable_ssh(self):
        result, changed = enable_ssh(SAMPLE_XML)
        assert changed
        assert 'SSHLanEnable="1"' in result

    def test_enable_ftp(self):
        result, changed = enable_ftp(SAMPLE_XML)
        assert changed
        assert 'FTPLanEnable="1"' in result

    def test_enable_telnet_already_on(self):
        result, changed = enable_telnet(SAMPLE_XML)
        assert changed  # regex sub matches even if value unchanged
        assert 'TELNETLanEnable="1"' in result

    def test_enable_ftp_service(self):
        result, changed = enable_ftp_service(SAMPLE_XML)
        assert changed
        assert 'FtpEnable="1"' in result

    def test_disable_cwmp(self):
        result, changed = disable_cwmp(SAMPLE_XML)
        assert changed
        assert 'EnableCWMP="0"' in result


class TestListFunctions:
    def test_list_cli_users(self):
        users = list_cli_users(SAMPLE_XML)
        assert len(users) == 1
        assert users[0]["Username"] == "root"
        assert users[0]["UserGroup"] == ""

    def test_list_acl_services(self):
        services = list_acl_services(SAMPLE_XML)
        assert len(services) == 1
        assert services[0]["SSHLanEnable"] == "0"
        assert services[0]["TELNETLanEnable"] == "1"


class TestUnlockAll:
    def test_unlock_all_root(self):
        result, changes = unlock_all(SAMPLE_XML, "root")
        assert len(changes) >= 5
        assert 'UserGroup="4294967295"' in result
        assert 'SSHLanEnable="1"' in result
        assert 'FTPLanEnable="1"' in result
        assert 'FtpEnable="1"' in result
        assert 'EnableCWMP="0"' in result

    def test_unlock_all_idempotent(self):
        result1, changes1 = unlock_all(SAMPLE_XML, "root")
        result2, changes2 = unlock_all(result1, "root")
        # Content should be identical even if regex reports changes
        assert result1 == result2
