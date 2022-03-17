#! /bin/sh
set -e
source /vagrant_data/env_vars

# Register the VM with Red Hat
subscription-manager register --username $RHN_USER --password $RHN_PASSWORD --auto-attach
dnf update -y

# Add the repo to install Postgres 13
dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -qy module disable postgresql

# Install required packages
dnf install -y postgresql13-server postgresql13-devel redis python3.9 python39-devel nginx

# Change python3
rm /usr/bin/python3
ln -s python3.9 /usr/bin/python3

# Initialize Postgres, set password
/usr/pgsql-13/bin/postgresql-13-setup initdb

# Setup SSL for Postgres
cp /src/tools/postgresql/postgresql.conf /var/lib/pgsql/13/data
cp /src/tools/postgresql/pg_hba.conf /var/lib/pgsql/13/data
mkdir /etc/ssl_config
cp /src/tools/postgresql/server.key /etc/ssl_config
cp /src/tools/postgresql/root.crt /etc/ssl_config
cp /src/tools/postgresql/server.crt /etc/ssl_config
chown postgres -R /etc/ssl_config
chmod 0600 /etc/ssl_config/*

systemctl enable --now postgresql-13
sudo -u postgres psql -c "ALTER USER $PINAKES_POSTGRES_USER PASSWORD '$PINAKES_POSTGRES_PASSWORD';"


cp -R /src /opt/pinakes
cd /opt/pinakes/

# In some of the dev env they might have their own venv which we should
# delete from this vm
if [ -d "venv" ]
then
    rm -rf venv
fi

export PATH="$PATH:/usr/pgsql-13/bin"
python3 -m venv venv
source /opt/pinakes/venv/bin/activate
pip3 install -U pip
pip3 install -r requirements.txt

# This jinja2  is needed so we can create the service files with the env vars filled in
pip3 install jinja2

# Configure Catalog Settings for Keycloak
dnf install -y ansible
ansible-galaxy collection install community.general mkanoor.catalog_keycloak
ansible-playbook tools/keycloak_setup/dev.yml


# Create the Catalog Database
sql="CREATE DATABASE "$PINAKES_DATABASE_NAME";"
echo $sql > /tmp/my.sql
export PGPASSWORD=$PINAKES_POSTGRES_PASSWORD
psql -v ON_ERROR_STOP=1 -h "$PINAKES_POSTGRES_HOST" -U "$PINAKES_POSTGRES_USER" -f /tmp/my.sql

# Run the migration
python3 manage.py migrate

# Fetch the UI Tar
curl -o ui.tar.xz -L https://github.com/ansible/pinakes-ui/releases/download/latest/catalog-ui.tar.gz
mkdir -p pinakes/ui/catalog
tar -xf ui.tar.xz --directory pinakes/ui/catalog

# Clear out the old static and media directories, if we run
# the provision multiple times
# Both of these directories have to point to somewhere in
# /var/lib so the nginx process can access it, else SELinux will
# block it.
rm -rf $PINAKES_STATIC_ROOT
rm -rf $PINAKES_MEDIA_ROOT

mkdir -p $PINAKES_STATIC_ROOT
mkdir -p $PINAKES_MEDIA_ROOT

python3 manage.py collectstatic --noinput

# Create the 3 service files by resolving the env vars
python3 /vagrant_data/scripts/apply_env.py /vagrant_data/catalog/services/catalog.service.j2 /etc/systemd/system/catalog.service
python3 /vagrant_data/scripts/apply_env.py /vagrant_data/catalog/services/catalog_scheduler.service.j2 /etc/systemd/system/catalog_scheduler.service
python3 /vagrant_data/scripts/apply_env.py /vagrant_data/catalog/services/catalog_worker.service.j2 /etc/systemd/system/catalog_worker.service

adduser "$PINAKES_SERVICE_USER"
chown "$PINAKES_SERVICE_USER"."$PINAKES_SERVICE_USER" -R /opt/pinakes
# Catalog should be able to write to the media directory
chown "$PINAKES_SERVICE_USER"."$PINAKES_SERVICE_USER" -R $PINAKES_MEDIA_ROOT

systemctl daemon-reload
systemctl enable --now redis
systemctl enable --now catalog
systemctl enable --now catalog_worker
systemctl enable --now catalog_scheduler


# Configure nginx
cp /vagrant_data/nginx/ssl/catalog.vm.local.key /etc/ssl/catalog.key
cp /vagrant_data/nginx/ssl/catalog.vm.local.crt /etc/ssl/catalog.crt
python3 /vagrant_data/scripts/apply_env.py /vagrant_data/nginx/conf/catalog-nginx.conf.j2 /etc/nginx/conf.d/catalog-nginx.conf

systemctl enable nginx
systemctl restart nginx

firewall-cmd --permanent --add-service=https
systemctl stop firewalld
systemctl start firewalld

# To connect to the catalog app running locally we need this
# SELinux policy enabled
setsebool -P httpd_can_network_connect on
