#!/usr/bin/python

from ansible.module_utils.basic import *

import requests
from requests.auth import HTTPBasicAuth


def artifactory_license(data):

    headers = {
        "Content-Type": "application/json"
    }

    user = data['user']
    password = data['password']
    del data['user']
    del data['password']
    url = "{}/{}".format(data['artifactory'], 'api/system/license')
    result = requests.post(url, json.dumps(data), headers=headers, auth=HTTPBasicAuth(user, password))

    if result.status_code == 200:
        return False, True, result.json()

    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.json()}
    return True, False, meta


def main():
    fields = {
        "artifactory": {"required": True, "type": "str"},
        "licenseKey": {"required": True, "type": "str"},
        "user": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"}
    }
    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = artifactory_license(module.params)
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error adding license", meta=result)


if __name__ == '__main__':
    main()
