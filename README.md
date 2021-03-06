Ansible jfrog module
==========

# Introduction
Ansible modules to interact with an artifactory instance.

# Installation

To use this custom module, it must be on the ansible library path. Add the following to your `/etc/ansible/ansible.cfg`:

    library = /usr/share/my_modules/:/opt/ansible-modules

Then, to clone the repo:

    sudo mkdir -p /opt/ansible-roles
    sudo chown -R <user>:<group> /opt/ansible-modules
    cd /opt/ansible-roles
    git clone https://github.com/William1444/ansible-module-artifactory

# Usage

## Repository
Ensure a repository is present
```yaml
- name: Create an artifactory repo
      artifactory_repo:
        artifactory: "https://artifactory.com/artifactory/"
        user: "admin_user"
        password: "admin_user_password"
        key: "docker-local"
        packageType: "docker"
        description: "A docker repo"
      register: result
```

Ensure a repository is absent
```yaml
- name: Delete an artifactory repo
      artifactory_repo:
        artifactory: "https://artifactory.com/artifactory/"
        user: "admin_user"
        password: "admin_user_password"
        key: "docker-local"
        packageType: "docker"
        description: "A docker repo"
        state: "absent"
      register: result
```

# Development

## Debugging

For debugging the module, use the ansible `test-module` python script. First install it:
  
    git clone git://github.com/ansible/ansible.git --recursive
    
Then setup the environment to use it:

    . ./ansible/hacking/env-setup
    
Then execute the module with params, for example:

    ./ansible/hacking/test-module -m ./library/artifactory_repo.py -a "artifactory='https://artifactory.com/artifactory/' packageType=docker key='docker-local1' password='<admin_user_password>' user='<admin_user>'"
    
To test the user module:

    ./ansible/hacking/test-module -m ./library/artifactory_user.py -a "artifactory='https://artifactory.is-in-the.cloud/artifactory/' admin_user='<admin_user>' admin_user_password='<admin_password>' name='<user_to_delete>' state='absent'"
    
Without this you will not see print statements, or the underlying issue causing module failures.

## Testing

Ensure the test playbooks included here work with the module. Setup the python venv:

    virtualenv venv
    . ./venv/bin/activate
    pip install -r requirements.txt

Test the ensure absent playbook by running

    ansible-playbook playbooks/play-artifactory-repo-delete.yml

Test the ensure present playbook by running
    
    ansible-playbook playbooks/play-artifactory-repo-create.yml
    
And so on for all playbooks

Run each multiple times to ensure the module handles scenarios where the repo is already in the desired state.

# TODO

Create gitlab pipeline

Auto deploy to ansible control nodes

Automate the test runs so that they can work in the gitlab pipeline

# License

Copyright 2016 William Lacy

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Author

William Lacy
