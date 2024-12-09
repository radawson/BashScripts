#!/bin/bash

sudo apt update
sudo apt-get -y install curl apt-transport-https gnupg

# Set US_en locale
sudo locale-gen en_US.UTF-8
echo "LANG=en_US.UTF-8" | sudo tee /etc/default/locale

# Set timezone
sudo timedatectl set-timezone America/New_York

# Install Postgres
sudo apt install -y postgresql-common
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
sudo apt update
sudo apt-get -y install postgresql postgresql-contrib

# Create the Zammad user and database
#sudo -u postgres psql -c "CREATE USER zammad WITH SUPERUSER CREATEDB CREATEROLE INHERIT LOGIN ENCRYPTED PASSWORD 'zammad';"

# Install Nginx
sudo apt-get -y install nginx

# Install Redis
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
sudo chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt-get install -y redis

# Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Add Zammad repository
curl -fsSL https://dl.packager.io/srv/zammad/zammad/key | \
   gpg --dearmor | sudo tee /etc/apt/keyrings/pkgr-zammad.gpg> /dev/null
  
#echo "deb [signed-by=/etc/apt/trusted.gpg.d/pkgr-zammad.gpg] https://dl.packager.io/srv/deb/zammad/zammad/stable/ubuntu 22.04 main"| \
#   sudo tee /etc/apt/sources.list.d/zammad.list > /dev/null
   
echo "deb [signed-by=/etc/apt/keyrings/pkgr-zammad.gpg] https://dl.packager.io/srv/deb/zammad/zammad/stable/ubuntu 24.04 main"| \
   sudo tee /etc/apt/sources.list.d/zammad.list > /dev/null
   
# Set up firewall
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable
  
# Install software
sudo apt update

sudo apt-get -y install elasticsearch | tee elasticsearch.txt

sudo sed -i 's/xpack.security.enabled: true/xpack.security.enabled: false/' /etc/elasticsearch/elasticsearch.yml
cat | sudo tee -a /etc/elasticsearch/elasticsearch.yml <<EOF

# Tickets above this size (articles + attachments + metadata)
# may fail to be properly indexed (Default: 100mb).
#
# When Zammad sends tickets to Elasticsearch for indexing,
# it bundles together all the data on each individual ticket
# and issues a single HTTP request for it.
# Payloads exceeding this threshold will be truncated.
#
# Performance may suffer if it is set too high.
http.max_content_length: 400mb

# Allows the engine to generate larger (more complex) search queries.
# Elasticsearch will raise an error or deprecation notice if this value is too low,
# but setting it too high can overload system resources (Default: 1024).
#
# Available in version 6.6+ only.
indices.query.bool.max_clause_count: 2000
EOF

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl restart elasticsearch


sudo apt-get -y install zammad

# Set the Elasticsearch server address
#sudo /usr/share/elasticsearch/bin/elasticsearch-plugin install ingest-attachment
#sudo zammad run rails r "Setting.set('es_user', 'zammad')"
#sudo zammad run rails r "Setting.set('es_password', 'zammad')"
sudo zammad run rails r "Setting.set('es_url', 'http://localhost:9200')"


# Build the search index
sudo zammad run rake zammad:searchindex:rebuild
sudo zammad run rails r "Setting.set('es_attachment_ignore',\
  [ '.png', '.jpg', '.jpeg', '.mpeg', '.mpg', '.mov', '.bin', '.exe', '.box', '.mbox' ] )"
  
sudo cp /opt/zammad/contrib/nginx/zammad_ssl.conf /etc/nginx/sites-available/zammad.conf