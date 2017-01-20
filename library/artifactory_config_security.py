#!/usr/bin/python

from ansible.module_utils.basic import *

import requests
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree
import re


def artifactory_config_security(data):
    headers = {
        "Content-Type": "application/xml"
    }

    user = data['user']
    password = data['password']
    del data['user']
    del data['password']
    data['enabled'] = 'true' if data['enabled'] else 'false'
    data['autoCreateUser'] = 'true' if data['autoCreateUser'] else 'false'
    data['ldapPoisoningProtection'] = 'true' if data['ldapPoisoningProtection'] else 'false'
    data['searchSubTree'] = 'true' if data['searchSubTree'] else 'false'
    data['searchBase'] = data['searchBase'] if data['searchBase'] else ''
    url = "{}/{}".format(data['artifactory'], 'api/system/configuration')
    current_config_response = requests.get(url, auth=HTTPBasicAuth(user, password))
    current_config_tree = ElementTree.fromstring(current_config_response.content)

    changed = False
    updated_existing = False
    found_existing_key = False
    namespace = re.sub(r'config$', '', current_config_tree.tag)
    security_settings = current_config_tree.find('{}security'.format(namespace))
    ldap_settings = security_settings.find('{}ldapSettings'.format(namespace))

    def append_ldap_el(append_to):
        ns = 'ns0:'
        ldap_setting_el = ElementTree.SubElement(append_to, ns + 'ldapSetting')
        for el_key in ['key', 'enabled', 'ldapUrl', 'userDnPattern']:
            el = ElementTree.SubElement(ldap_setting_el, ns + el_key)
            el.text = str(data[el_key])
        new_search_el = ElementTree.SubElement(ldap_setting_el, ns + 'search')
        for new_search_el_key in ['searchFilter', 'searchBase', 'searchSubTree', 'managerDn', 'managerPassword']:
            el = ElementTree.SubElement(new_search_el, ns + new_search_el_key)
            el.text = str(data[new_search_el_key])

        for el_key in ['autoCreateUser', 'emailAttribute', 'ldapPoisoningProtection']:
            el = ElementTree.SubElement(ldap_setting_el, ns + el_key)
            el.text = str(data[el_key])

    def replace_ldap_setting(el_to_remove):
        ldap_settings.remove(el_to_remove)
        append_ldap_el(ldap_settings)

    for ldap_setting in ldap_settings.findall('{}ldapSetting'.format(namespace)):
        key = ldap_setting.find('{}key'.format(namespace))
        if key.text == data['key']:
            found_existing_key = True
            for ldap_setting_el_key in ['enabled', 'ldapUrl', 'userDnPattern', 'autoCreateUser', 'emailAttribute',
                                        'ldapPoisoningProtection']:
                e = ldap_setting.find(namespace + ldap_setting_el_key)
                if e.text != data[ldap_setting_el_key]:  # it exists but the values are not what we were expecting
                    replace_ldap_setting(ldap_setting)
                    changed = True
                    break

            if not updated_existing:  # continue looking through the deeper elements
                search_el = ldap_setting.find('{}search'.format(namespace))
                for search_el_key in ['searchFilter', 'searchBase', 'searchSubTree', 'managerDn', 'managerPassword']:
                    e = search_el.find(namespace + search_el_key)
                    e_text = e.text if e.text else ''
                    if e_text != data[search_el_key]:  # it exists but the values are not what we were expecting
                        replace_ldap_setting(ldap_setting)
                        changed = True
                        break

    if not found_existing_key:  # it did not already exist
        append_ldap_el(ldap_settings)
        changed = True

    if changed:
        f = open('.tmp.xml', 'w')
        f.write(ElementTree.tostring(current_config_tree, encoding='utf8', method='xml'))
        result = requests.post(url, data=ElementTree.tostring(current_config_tree, encoding='utf8', method='xml'),
                               headers=headers, auth=HTTPBasicAuth(user, password))
        meta = {"status": result.status_code, 'response': result.text}
        if result.status_code == 200:
            return False, True, meta
        else:
            return True, False, meta
    else:
        return False, changed, json.dumps({})


def main():
    fields = {
        "artifactory": {"required": True, "type": "str"},
        "user": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"},
        "key": {"required": True, "type": "str"},
        "enabled": {"default": True, "type": "bool"},
        "ldapUrl": {"required": True, "type": "str"},
        "userDnPattern": {"required": True, "type": "str"},
        "searchFilter": {"required": True, "type": "str"},
        "searchBase": {"default": "", "type": "str"},
        "searchSubTree": {"default": True, "type": "bool"},
        "managerDn": {"required": True, "type": "str"},
        "managerPassword": {"required": True, "type": "str"},
        "autoCreateUser": {"default": True, "type": "bool"},
        "emailAttribute": {"default": "mail", "type": "str"},
        "ldapPoisoningProtection": {"default": True, "type": "bool"}
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = artifactory_config_security(module.params)
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error updating security", meta=result)


if __name__ == '__main__':
    main()
