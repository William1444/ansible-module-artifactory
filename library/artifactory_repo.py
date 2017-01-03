#!/usr/bin/python

from ansible.module_utils.basic import *

import requests
from requests.auth import HTTPBasicAuth


def github_repo_present(data):

    del data['state']

    headers = {
        "Content-Type": "application/json"
    }

    del data['user']
    del data['password']
    url = "{}/{}/{}".format(data['artifactory'], 'api/repositories', data['key'])
    result = requests.put(url, json.dumps(data), headers=headers, auth=HTTPBasicAuth('admin', 'password'))

    if result.status_code == 200:
        return False, True, {"status": result.status_code}
    elif result.status_code == 400 and 'errors' in result.json():
        for errors in result.json()['errors']:
            if 'key already exists' in errors['message']:
                return False, False, result.json()
    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.json()}
    return True, False, meta


def github_repo_absent(data=None):
    url = "{}/{}/{}".format(data['artifactory'], 'api/repositories', data['key'])
    result = requests.delete(url, auth=HTTPBasicAuth('admin', 'password'))

    if result.status_code == 200:
        return False, True, {"status": result.status_code}
    elif result.status_code == 404 and 'errors' in result.json():
        for errors in result.json()['errors']:
            if 'does not exist' in errors['message']:
                return False, False, result.json()
    # default: something went wrong
    meta = {"status": result.status_code, 'response': result.json()}
    return True, False, meta


def main():
    fields = {
        "artifactory": {"required": True, "type": "str"},
        "key": {"required": True, "type": "str"},
        "rclass": {
            "default": "local",
            "choices": ['local', 'remote', 'virtual'],
            "type": 'str'
        },
        "packageType": {
            "required": True,
            "choices": ["maven", "gradle", "ivy", "sbt", "nuget", "gems", "npm", "bower", "pypi", "docker", "p2",
                        "generic"],
            "type": 'str'
        },
        "description": {"required": False, "type": "str"},
        "user": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ['present', 'absent'],
            "type": 'str'
        },
    }
    choice_map = {
        "present": github_repo_present,
        "absent": github_repo_absent,
    }
    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result = choice_map.get(module.params['state'])(module.params)
    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error deleting repo", meta=result)


if __name__ == '__main__':
    main()
