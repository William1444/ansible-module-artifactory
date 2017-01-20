#!/usr/bin/python

from ansible.module_utils.basic import *

import requests
from requests.auth import HTTPBasicAuth
from xml.etree import ElementTree
import re
sys.path.insert(0, '../utils')

SECURITY_ENDPOINT = 'api/system/configuration'


def set_current_config(data, xml_tree):
    headers = {
        "Content-Type": "application/xml"
    }
    return requests.post("{}/{}".format(data['artifactory'], SECURITY_ENDPOINT),
                  data=ElementTree.tostring(xml_tree, encoding='utf8', method='xml'),
                  headers=headers, auth=HTTPBasicAuth(data['user'], data['password']))


def get_current_config(data):
    '''

    :param artifactory_base: base arti url
    :param user: username for rest req
    :param password: password for rest req
    :return: namespace for xml and current_config_tree as xml.etree.ElementTree
    '''
    resp = requests.get("{}/{}".format(data['artifactory'], SECURITY_ENDPOINT),
                        auth=HTTPBasicAuth(data['user'], data['password']))
    current_config_tree = ElementTree.fromstring(resp.content)
    ns = re.sub(r'config$', '', current_config_tree.tag)
    return ns, current_config_tree


def replace_ldap_setting(data, ldap_settings, el_to_remove):
    ldap_settings.remove(el_to_remove)
    append_ldap_el(data, ldap_settings)


def append_ldap_el(data, append_to):
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


def artifactory_config_security_absent(data):
    changed = False
    ns, current_config_tree = get_current_config(data)
    security_settings = current_config_tree.find('{}security'.format(ns))
    ldap_settings = security_settings.find('{}ldapSettings'.format(ns))

    for ldap_setting in ldap_settings.findall('{}ldapSetting'.format(ns)):
        key = ldap_setting.find('{}key'.format(ns))
        if key.text == data['key']:
            ldap_settings.remove(ldap_setting)
            result = set_current_config(data, current_config_tree)
            meta = {"status": result.status_code, 'response': result.text}
            if result.status_code == 200:
                changed = True
                return False, changed, meta
            else:
                return True, changed, meta
    return False, changed, ''


def artifactory_config_security_present(data):
    data['enabled'] = 'true' if data['enabled'] else 'false'
    data['autoCreateUser'] = 'true' if data['autoCreateUser'] else 'false'
    data['ldapPoisoningProtection'] = 'true' if data['ldapPoisoningProtection'] else 'false'
    data['searchSubTree'] = 'true' if data['searchSubTree'] else 'false'
    data['searchBase'] = data['searchBase'] if data['searchBase'] else ''
    ns, current_config_tree = get_current_config(data)
    changed = False
    updated_existing = False
    found_existing_key = False
    security_settings = current_config_tree.find('{}security'.format(ns))
    ldap_settings = security_settings.find('{}ldapSettings'.format(ns))

    for ldap_setting in ldap_settings.findall('{}ldapSetting'.format(ns)):
        key = ldap_setting.find('{}key'.format(ns))
        if key.text == data['key']:
            found_existing_key = True
            for ldap_setting_el_key in ['enabled', 'ldapUrl', 'userDnPattern', 'autoCreateUser', 'emailAttribute',
                                        'ldapPoisoningProtection']:
                e = ldap_setting.find(ns + ldap_setting_el_key)
                if e.text != data[ldap_setting_el_key]:  # it exists but the values are not what we were expecting
                    replace_ldap_setting(data, ldap_settings, ldap_setting)
                    changed = True
                    break

            if not updated_existing:  # continue looking through the deeper elements
                search_el = ldap_setting.find('{}search'.format(ns))
                for search_el_key in ['searchFilter', 'searchBase', 'searchSubTree', 'managerDn', 'managerPassword']:
                    e = search_el.find(ns + search_el_key)
                    e_text = e.text if e.text else ''
                    if e_text != data[search_el_key]:  # it exists but the values are not what we were expecting
                        replace_ldap_setting(data, ldap_settings, ldap_setting)
                        changed = True
                        break

    if not found_existing_key:  # it did not already exist
        append_ldap_el(data, ldap_settings)
        changed = True

    if changed:
        result = set_current_config(data, current_config_tree)
        meta = {"status": result.status_code, 'response': result.text}
        if result.status_code == 200:
            return False, True, meta
        else:
            return True, False, meta
    else:
        return False, changed, json.dumps({})


def main():
    base_fields = {
        "artifactory": {"required": True, "type": "str"},
        "user": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"},
        "key": {"required": True, "type": "str"}
    }

    choice_map = {
        "present": artifactory_config_security_present,
        "absent": artifactory_config_security_absent
    }
    # create a base module to enable access to the parsed params for craeting a dynamic arg spec
    base_module = AnsibleModule(argument_spec=base_fields, check_invalid_arguments=False)
    is_present = base_module.params['state'] == 'present'
    base_fields.update({"enabled": {"default": True, "type": "bool"},
                        "ldapUrl": {"required": is_present, "type": "str"},
                        "userDnPattern": {"required": is_present, "type": "str"},
                        "searchFilter": {"required": is_present, "type": "str"},
                        "searchBase": {"default": "", "type": "str"},
                        "searchSubTree": {"default": is_present, "type": "bool"},
                        "managerDn": {"required": is_present, "type": "str"},
                        "managerPassword": {"required": is_present, "type": "str"},
                        "autoCreateUser": {"default": is_present, "type": "bool"},
                        "emailAttribute": {"default": "mail", "type": "str"},
                        "ldapPoisoningProtection": {"default": is_present, "type": "bool"},
                        "state": {"default": "present", "choices": ["present", "absent"]}})
    # re-init module with the dynamic arg spec
    module = AnsibleModule(argument_spec=base_fields)
    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)

    if not is_error:
        base_module.exit_json(changed=has_changed, meta=result)
    else:
        base_module.fail_json(msg="Error updating security", meta=result)


if __name__ == '__main__':
    main()
