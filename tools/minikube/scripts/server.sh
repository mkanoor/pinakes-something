#!/bin/bash

echo -e "\e[34m >>> Installing keycloak setup collections \e[97m"
mkdir /tmp/collections
export ANSIBLE_CFG=/tmp/.ansible
export ANSIBLE_COLLECTIONS_PATH=/tmp/collections
export ANSIBLE_COLLECTIONS_PATHS=/tmp/collections
export ANSIBLE_LOCAL_TEMP=/tmp

ansible-galaxy collection install community.general
ansible-galaxy collection install mkanoor.catalog_keycloak
ansible-playbook -vvv tools/keycloak_setup/dev.yml

echo -e "\e[34m >>> Migrating changes \e[97m"
python manage.py migrate
echo -e "\e[32m >>> migration completed \e[97m"

echo -e "\e[34m >>> Start development server \e[97m"
python manage.py runserver 0.0.0.0:8000
