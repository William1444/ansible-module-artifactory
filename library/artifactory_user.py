#!/usr/bin/python

from ansible.module_utils.basic import *

import requests
from requests.auth import HTTPBasicAuth


def artifactory_repo_present(data):

    # Additionally required params if creating user
    required_arguments = ['email', 'password']
    missing = []

    for required_argument in required_arguments:
        if required_argument not in data or not data[required_argument]:
            missing.append(required_argument)
    if missing:
        return True, False, json.dumps({"msg": "missing required arguments: %s" % ",".join(missing)})

    del data['state']

    headers = {
        "Content-Type": "application/json"
    }

    user = data['admin_user']
    password = data['admin_user_password']
    del data['admin_user']
    del data['admin_user_password']
    url = "{}/{}/{}".format(data['artifactory'], 'api/security/users', data['name'])
    # try a create
    # Believe it or not, the put does the create/update
    result = requests.put(url, json.dumps(data), headers=headers, auth=HTTPBasicAuth(user, password))

    if result.status_code == 201:
        return False, True, {"status": result.status_code}
    # TODO do a get to check if the user already exists, and if so return changed is False. The API provides the same
    # Response regardless
    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.json()}
    return True, False, meta


def artifactory_repo_absent(data=None):
    user = data['admin_user']
    password = data['admin_user_password']
    url = "{}/{}/{}".format(data['artifactory'], 'api/security/users', data['name'])
    result = requests.delete(url, auth=HTTPBasicAuth(user, password))

    if result.status_code == 200:
        return False, True, {"status": result.status_code}
    elif result.status_code == 404:
        return False, False, result.json()
    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.text}
    return True, False, meta


def main():
    fields = {
        "artifactory": {"required": True, "type": "str"},
        "admin_user": {"required": True, "type": "str"},
        "admin_user_password": {"required": True, "type": "str"},

        "name": {"required": True, "type": "str"},
        "email": {"required": False, "type": "str"},  # required if state=present
        "password": {"required": False, "type": "str"},  # required if state=present
        "admin": {"type": "str", "default": "false"},
        "groups": {"type": "list", "default": []},
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        }
    }
    choice_map = {
        "present": artifactory_repo_present,
        "absent": artifactory_repo_absent,
    }
    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error removing user", meta=result)


if __name__ == '__main__':
    main()
