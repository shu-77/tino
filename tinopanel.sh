
gen_pass() {
    MATRIX='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    LENGTH=16
    while [ ${n:=1} -le $LENGTH ]; do
        PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
        let n+=1
    done
    echo "$PASS"
}
yum -y install gawk bc wget lsof
printf "Ban hay lua chon phien ban PHP muon su dung:\n"
prompt="Nhap vao lua chon cua ban [1-8]: "
php_version="7.4"; # Default PHP 7.3
options=("PHP 7.4" "PHP 7.3" "PHP 7.2" "PHP 7.1" "PHP 7.0" "PHP 5.6" "PHP 7.2 va PHP 5.6" "CAI DAT TAT CA PHIEN BAN PHP 7.4, 7.3, 7.2, 7.1, 7.0. 5.6 ")
PS3="$prompt"
select opt in "${options[@]}"; do 

    case "$REPLY" in
    1) php_version="7.4"; break;;
    2) php_version="7.3"; break;;
    3) php_version="7.2"; break;;
    4) php_version="7.1"; break;;
    5) php_version="7.0"; break;;
    6) php_version="5.6"; break;;
    7) php_version="7.2.5.6"; break;;
    8) php_version="5.6.7.4"; break;;	
    $(( ${#options[@]}+1 )) ) printf "\nHe thong se cai dat PHP 7.4\n"; break;;
    *) printf "Ban nhap sai, he thong cai dat PHP 7.4\n"; break;;
    esac    
done


printf "\nNhap vao port admin roi an [ENTER]: " 
read admin_port
if [ "$admin_port" == "" ] || [ $admin_port == "2222" ] || [ $admin_port -lt 2000 ] || [ $admin_port -gt 9999 ] || [ $(lsof -i -P | grep ":$admin_port " | wc -l) != "0" ]; then
	admin_port=$(date +'%Y')
	echo "Port admin khong phu hop. He thong su dung port mac dinh la $admin_port"
	echo
fi



rm -f /etc/localtime
ln -sf /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime

if [ -s /etc/selinux/config ]; then
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
fi
setenforce 0

# Install EPEL + Remi Repo
yum -y install epel-release yum-utils
rpm -Uvh http://rpms.famillecollet.com/enterprise/remi-release-7.rpm

systemctl stop  saslauthd.service
systemctl disable saslauthd.service

# Disable the FirewallD Service and use Iptables instead because FirewallD need reboot in order to start
systemctl stop firewalld
systemctl disable firewalld
systemctl mask firewalld

yum -y remove mysql* php* httpd* sendmail* postfix* rsyslog*
yum clean all
yum -y update

cd /root/

yum install -y epel-release
yum install -y cmake3 cmake zlib-devel --enablerepo=epel 
yum install -y git wget zip unzip perl-ExtUtils-Embed pam-devel gcc gcc-c++ make geoip-devel httpd-tools libxml2-devel libXpm-devel gmp-devel libicu-devel t1lib-devel aspell-devel openssl-devel bzip2-devel libcurl-devel libjpeg-devel libvpx-devel libpng-devel freetype-devel readline-devel libtidy-devel libxslt-devel libmcrypt-devel pcre-devel curl-devel mysql-devel ncurses-devel gettext-devel net-snmp-devel libevent-devel libtool-ltdl-devel libc-client-devel postgresql-devel php-pecl-zip libzip-devel libuuid-devel  net-tools
yum groupinstall -y 'Development Tools'

# Install Others
yum -y install exim syslog-ng syslog-ng-libdbi cronie unzip zip nano openssl ntpdate

ntpdate asia.pool.ntp.org
hwclock --systohc


## download file install 

git clone https://github.com/tinopanel/tino.git

tino='/root/tino'

# cai dat nginx

cd $tino/nginx/nginx*
RUN_COMPILE_NGINX
make && make install
openssl dhparam 2048 -out /etc/nginx/dhparam.pem
CREATE_USER_NGINX
CREATE_STARTUP_SCRIPT_NGX
systemctl start nginx.service
systemctl enable nginx.service


# install  php-fpm
useradd -M -s /bin/nologin tinopanel

if [ "$php_version" = "7.4" ]; then
	COMPILE_PHP_7_4
	rm -rf /opt/php74/etc/php-fpm.d/*
	cd /opt/php74/etc/php-fpm.d/
	TINOPOOL	
	systemctl start php-fpm-74.service
	systemctl enable php-fpm-74.service
	echo "Finshed compile PHP 7.4 ..."
			sleep 10

elif [ "$php_version" = "7.3" ]; then
        COMPILE_PHP_7_3
        rm -rf /opt/php73/etc/php-fpm.d/*
	cd /opt/php73/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-73.service
        systemctl enable php-fpm-73.service
        echo "Finshed compile PHP 7.3 ,..."
                        sleep 10
elif [ "$php_version" = "7.2" ]; then
        COMPILE_PHP_7_2
	cd /opt/php72/etc/php-fpm.d/
	rm -rf /opt/php72/etc/php-fpm.d/*
        TINOPOOL
        systemctl start php-fpm-72.service
        systemctl enable php-fpm-72.service
        echo "Finshed compile PHP 7.2,..."
                        sleep 10
elif [ "$php_version" = "7.1" ]; then
        COMPILE_PHP_7_1
        rm -rf /opt/php71/etc/php-fpm.d/*
	cd /opt/php71/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-71.service
        systemctl enable php-fpm-71.service
        echo "Finshed compile PHP 7.1,..."
                        sleep 10
elif [ "$php_version" = "7.0" ]; then
        COMPILE_PHP_7_0
        rm -rf /opt/php70/etc/php-fpm.d/*
	cd /opt/php70/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-70.service
        systemctl enable php-fpm-70.service
        echo "Finshed compile PHP 7.0,..."
                        sleep 10
elif [ "$php_version" = "7.2.5.6" ]; then
        COMPILE_PHP_7_2
	COMPILE_PHP_5_6
        rm -rf /opt/php72/etc/php-fpm.d/*
        rm -rf /opt/php56/etc/php-fpm.d/*
	cd /opt/php72/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-72.service
        systemctl enable php-fpm-72.service
        systemctl start php-fpm-56.service
        systemctl enable php-fpm-56.service
        echo "Finshed compile PHP 7.2 and 5.6,..."
                        sleep 10
elif [ "$php_version" = "7.4.5.6" ]; then
        COMPILE_PHP_7_4
        COMPILE_PHP_7_3
        COMPILE_PHP_7_2
        COMPILE_PHP_7_1
        COMPILE_PHP_7_0
        COMPILE_PHP_5_6
	rm -rf /opt/php74/etc/php-fpm.d/*
        rm -rf /opt/php73/etc/php-fpm.d/*
        rm -rf /opt/php72/etc/php-fpm.d/*
        rm -rf /opt/php71/etc/php-fpm.d/*
        rm -rf /opt/php70/etc/php-fpm.d/*
        rm -rf /opt/php56/etc/php-fpm.d/*
	cd /opt/php74/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-74.service
        systemctl enable php-fpm-74.service
        systemctl start php-fpm-73.service
        systemctl enable php-fpm-73.service
        systemctl start php-fpm-72.service
        systemctl enable php-fpm-72.service
        systemctl start php-fpm-71.service
        systemctl enable php-fpm-71.service
        systemctl start php-fpm-70.service
        systemctl enable php-fpm-70.service
        systemctl start php-fpm-56.service
        systemctl enable php-fpm-56.service

        echo "Finshed compile PHP 7.4, 7.3, 7.2, 7.1, 7.0, 5.6 ..."
                        sleep 10
elif [ "$php_version" = "5.6" ]; then
        COMPILE_PHP_5_6
        rm -rf /opt/php56/etc/php-fpm.d/*
	cd /opt/php56/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-56.service
        systemctl enable php-fpm-56.service
        echo "Finshed compile PHP 5.6,..."
                        sleep 10
else
        COMPILE_PHP_7_4
        rm -rf /opt/php74/etc/php-fpm.d/*
	cd /opt/php74/etc/php-fpm.d/
        TINOPOOL
        systemctl start php-fpm-74.service
        systemctl enable php-fpm-74.service
        echo "Finshed compile PHP 7.4,..."
                        sleep 10
fi


# vhost nginx
mkdir -p /home/tinopanel
mkdir -p /home/tinopanel/logs
mkdir -p /home/tinopanel/private_html
mkdir -p /home/tinopanel/ssl
cd /home/tinopanel/ssl
server_name = "tinopanel"
admin_password=$(gen_pass)
openssl dhparam 2048 -out /etc/nginx/dhparam.pem
openssl genrsa -out server.key 2048
openssl rsa -in server.key -out server.key
openssl req -sha256 -new -key server.key -out server.csr -subj '/CN=localhost'
openssl x509 -req -sha256 -days 3650 -in server.csr -signkey server.key -out server.crt
printf "admin:$(openssl passwd -apr1 $admin_password)\n" > /home/tinopanel/ssl/.htpasswd
ulimit -n 524288
rm -rf /etc/nginx/conf.d/*
cat > "/etc/nginx/conf.d/tinopanel.conf" <<END
server {
	listen $admin_port ssl;
 	access_log off;
	log_not_found off;
 	error_log /home/$server_name/logs/nginx_error.log;
	
    	root /home/$server_name/private_html;
	index index.php index.html index.htm;
    	server_name localhost;
	
	#ssl
	ssl_certificate /home/tinopanel/ssl/server.crt;
	ssl_certificate_key /home/tinopanel/ssl/server.key;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2; 
	ssl_prefer_server_ciphers on; 
	ssl_ciphers EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;

	auth_basic "Restricted";
	auth_basic_user_file /home/tinopanel/ssl/.htpasswd;
     	location / {
		autoindex on;
		try_files \$uri \$uri/ /index.php;
	}
	
    	location ~ \.php$ {
		fastcgi_split_path_info ^(.+\.php)(/.+)$;
        	include /etc/nginx/fastcgi_params;
        	fastcgi_pass /dev/shm/tinopanel.sock;
        	fastcgi_index index.php;
		fastcgi_connect_timeout 1000;
		fastcgi_send_timeout 1000;
		fastcgi_read_timeout 1000;
		fastcgi_buffer_size 256k;
		fastcgi_buffers 4 256k;
		fastcgi_busy_buffers_size 256k;
		fastcgi_temp_file_write_size 256k;
		fastcgi_intercept_errors on;
    	}
	
	location ~ /\. {
		deny all;
	}
}
END

## maridb repo
cat > "/etc/yum.repos.d/MariaDB.repo" <<END
# MariaDB 10.4 CentOS repository list - created 2020-05-14 18:59 UTC
# http://downloads.mariadb.org/mariadb/repositories/
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.4/centos7-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
END
systemctl restart nginx.service


## install mariadb

yum install MariaDB-server MariaDB-client -y

## config mariadb
cp /etc/my.cnf /etc/my.cnf-original
cat > "/etc/.my.cnf" <<END
[mysqld]
local-infile=0
innodb_file_per_table
max-connections=200
tmp_table_size = 128M
max_heap_table_size = 128M
myisam_sort_buffer_size = 64M
join_buffer_size = 64M
thread_cache_size = 50
table_open_cache = 100
wait_timeout = 120
interactive_timeout = 120
sql-mode="NO_ENGINE_SUBSTITUTION"
END
root_password=$(gen_pass)
'/usr/bin/mysqladmin' -u root password "$root_password"
mysql -u root -p"$root_password" -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' IDENTIFIED BY '$admin_password' WITH GRANT OPTION;"
mysql -u root -p"$root_password" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost')"
mysql -u root -p"$root_password" -e "DELETE FROM mysql.user WHERE User=''"
mysql -u root -p"$root_password" -e "DROP User '';"
mysql -u root -p"$root_password" -e "DROP DATABASE test"
mysql -u root -p"$root_password" -e "FLUSH PRIVILEGES"
cat > "/root/.my.cnf" <<END
[client]
user=root
password=$root_password
END

chmod 600 /root/.my.cnf
systemctl stop mysql.service
systemctl restart mysql.service

echo "pass cuoi cung"
echo $root_password;
echo $admin_password;



## tinopool func

TINOPOOL(){
cat > "tinopanel.conf" <<END
[tinopanel]
listen = /dev/shm/tinopanel.sock;
user = tinopanel
group = tinopanel
listen.owner = nginx
listen.group = nginx
listen.mode = 0644
;listen.allowed_clients = 127.0.0.1
pm = ondemand
pm.max_children = 15
pm.start_servers = 5
pm.min_spare_servers = 3
pm.max_spare_servers = 10
pm.max_requests = 500
END
cat >>  "../../lib/php.ini" <<END
zend_extension=opcache.so
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=4000
opcache.max_wasted_percentage=5
opcache.use_cwd=1
opcache.validate_timestamps=1
opcache.revalidate_freq=60
opcache.fast_shutdown=1
opcache.blacklist_filename=/opt/opcache-default.blacklist
END
cat > /opt/opcache-default.blacklist <<END
/home/*/*/public_html/wp-content/plugins/backwpup/*
/home/*/*/public_html/wp-content/plugins/duplicator/*
/home/*/*/public_html/wp-content/plugins/updraftplus/*
/home/tinopanel/private_html/
END
}



## func nginx

CREATE_USER_NGINX() {
	if [ ! `cat /etc/passwd | grep nginx` ]; then
		groupadd -r nginx 
        useradd -r -s /sbin/nologin -M -c "nginx service" -g nginx nginx
		echo "Finished create user nginx, continues create startup script..."
		sleep 5
	else
		echo "existed user nginx, continues create startup script..."
		sleep 5
fi
}

RUN_COMPILE_NGINX() {
	./configure \
		--prefix=/etc/nginx  \
		--conf-path=/etc/nginx/nginx.conf  \
		--user=nginx  \
		--group=nginx  \
		--sbin-path=/usr/sbin/nginx  \
		--with-zlib=/root/tino/nginx/lib-1.2.11  \
		--with-http_stub_status_module  \
		--with-http_realip_module  \
		--with-openssl=/root/tino/nginx/openssl-1.0.2t
		--with-http_geoip_module  \
		--with-http_v2_module  \
		--without-http_memcached_module  \
		--with-http_ssl_module  \
		--with-http_gzip_static_module  \
		--with-http_perl_module  \
		--with-pcre  \
		--with-http_secure_link_module  \
		--without-mail_pop3_module  \
		--without-mail_imap_module  \
		--without-mail_smtp_module  \
		--without-http_split_clients_module  \
		--without-http_empty_gif_module  \
		--without-http_browser_module  \
		--without-http_userid_module  \
		--add-module=/root/tino/nginx/incubator-pagespeed-ngx-latest-stable  \
		--add-module=/root/tino/nginx/nginx/nginx-module-vts  \
		--add-module=/root/tino/nginx/ngx_cache_purge  \
		--add-module=/root/tino/nginx/testcookie-nginx-module  \
		--add-module=/root/tino/nginx/headers-more-nginx-module
}


CREATE_STARTUP_SCRIPT_NGX() {
cat > "/lib/systemd/system/nginx.service" <<END
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
END

mkdir -p /var/cache/nginx  >/dev/null 2>&1

cat > "/etc/nginx/nginx.conf" <<END
user nginx;
error_log logs/error.log;
worker_processes auto;
events {

    worker_connections 20000;
}
http {

    log_format rt_cache '$remote_addr - $upstream_cache_status [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent"';
    include mime.types;

    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;
    geoip_country /usr/share/GeoIP/GeoIP.dat;

    default_type application/octet-stream;
    sendfile on;
    server_tokens off;
    server_names_hash_max_size 10000;
    server_names_hash_bucket_size 1024;

    tcp_nopush on;
    tcp_nodelay on;

    keepalive_timeout 65;
    keepalive_requests 100000;

    gzip on;
    gzip_min_length 1100;
    gzip_disable "msie6";
    gzip_buffers 4 32k;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript application/x-javascript text/javascript text/xml application/xml application/rss+xml application/atom+xml application/rdf+xml;
    ignore_invalid_headers on;

    client_header_timeout 3m;
    client_body_timeout 3m;
    send_timeout 3m;

    reset_timedout_connection on;
    connection_pool_size 256;

    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    client_max_body_size 2048M;
    client_body_buffer_size 128k;
    request_pool_size 32k;
    output_buffers 1 32k;
    postpone_output 1460;
    include "/etc/nginx/conf.d/*.conf";

}
END

cat > "/etc/nginx/fastcgi.conf" <<END
fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING	  $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE	  $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;

fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI	  $document_uri;
fastcgi_param  DOCUMENT_ROOT	  $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;

fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
fastcgi_param  REDIRECT_STATUS    200;
END
cat > "/etc/nginx/fastcgiproxy.conf" <<END
set_real_ip_from 199.27.128.0/21;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
real_ip_header CF-Connecting-IP;
real_ip_recursive on;
END
}

# func php-fpm
COMPILE_PHP_7_4() {
cd /root/tino/php74/php-7*
./configure  '--prefix=/opt/php74' '--with-zlib-dir' '--enable-calendar' '--with-curl' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm'
make && make install
cp -f php.ini-production /opt/php74/lib/php.ini
upload_max_filesize=2048M
post_max_size=2048M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php74/lib/php.ini
done

cat > "/opt/php74/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php74/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php74/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/lib/systemd/system/php-fpm-74.service" <<END
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target
[Service]
Type=simple
PIDFile=/opt/php74/var/run/php-fpm.pid
ExecStart=/opt/php74/sbin/php-fpm --nodaemonize --fpm-config /opt/php74/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
END
}

COMPILE_PHP_7_3() {
cd /root/tino/php73/php-7*
./configure  '--prefix=/opt/php73' '--with-zlib-dir' '--with-freetype-dir' '--with-libxml-dir=/usr' '--enable-calendar' '--with-curl' '--with-gd' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--enable-zip' '--with-pcre-regex' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-jpeg-dir=/usr' '--with-png-dir=/usr' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm' '--enable-mbstring'
make && make install
cp -f php.ini-production /opt/php73/lib/php.ini
upload_max_filesize=2048M
post_max_size=2048M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php73/lib/php.ini
done

cat > "/opt/php73/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php73/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php73/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/lib/systemd/system/php-fpm-73.service" <<END
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target
[Service]
Type=simple
PIDFile=/opt/php73/var/run/php-fpm.pid
ExecStart=/opt/php73/sbin/php-fpm --nodaemonize --fpm-config /opt/php73/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
END
}
COMPILE_PHP_7_2() {
cd /root/tino/php72/php-7*
./configure  '--prefix=/opt/php72' '--with-zlib-dir' '--with-freetype-dir' '--with-libxml-dir=/usr' '--enable-calendar' '--with-curl' '--with-gd' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--enable-zip' '--with-pcre-regex' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-jpeg-dir=/usr' '--with-png-dir=/usr' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm' '--enable-mbstring'
make && make install
cp -f php.ini-production /opt/php72/lib/php.ini
upload_max_filesize=2048M
post_max_size=2048M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php72/lib/php.ini
done

cat > "/opt/php72/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php72/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php72/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/lib/systemd/system/php-fpm-72.service" <<END
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target
[Service]
Type=simple
PIDFile=/opt/php72/var/run/php-fpm.pid
ExecStart=/opt/php72/sbin/php-fpm --nodaemonize --fpm-config /opt/php72/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
END
}

COMPILE_PHP_7_1() {
cd /root/tino/php71/php-7*
./configure  '--prefix=/opt/php71' '--with-zlib-dir' '--with-freetype-dir' '--with-libxml-dir=/usr' '--enable-calendar' '--with-curl' '--with-mcrypt' '--with-gd' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--enable-zip' '--with-pcre-regex' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-jpeg-dir=/usr' '--with-png-dir=/usr' '--enable-gd-native-ttf' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm' '--enable-mbstring'
make && make install
cp -f php.ini-production /opt/php71/lib/php.ini
upload_max_filesize=2048M
post_max_size=2048M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php71/lib/php.ini
done

cat > "/opt/php71/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php71/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php71/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/home/$server_name/private_html/filemanager/config/.htusers.php" <<END

END
}

COMPILE_PHP_7_0() {
cd /root/tino/php70/php-7*
./configure  '--prefix=/opt/php70' '--with-zlib-dir' '--with-freetype-dir' '--with-libxml-dir=/usr' '--enable-calendar' '--with-curl' '--with-mcrypt' '--with-gd' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--enable-zip' '--with-pcre-regex' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-jpeg-dir=/usr' '--with-png-dir=/usr' '--enable-gd-native-ttf' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm' '--enable-mbstring'
make && make install
cp -f php.ini-production /opt/php70/lib/php.ini
upload_max_filesize=2048M
post_max_size=2048M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php70/lib/php.ini
done

cat > "/opt/php70/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php70/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php70/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/lib/systemd/system/php-fpm-70.service" <<END
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target
[Service]
Type=simple
PIDFile=/opt/php70/var/run/php-fpm.pid
ExecStart=/opt/php70/sbin/php-fpm --nodaemonize --fpm-config /opt/php70/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
END
}

COMPILE_PHP_5_6() {
cd /root/tino/php56/php-5*
./configure  '--prefix=/opt/php56' '--with-zlib-dir' '--with-freetype-dir' '--with-libxml-dir=/usr' '--enable-calendar' '--with-curl' '--with-mcrypt' '--with-gd' '--enable-inline-optimization' '--with-bz2' '--with-zlib' '--enable-sockets' '--enable-sysvsem' '--enable-sysvshm' '--enable-pcntl' '--enable-mbregex' '--with-mhash' '--enable-zip' '--with-pcre-regex' '--with-mysql-sock=/var/lib/mysql/mysql.sock' '--with-pdo-mysql' '--with-mysqli' '--with-jpeg-dir=/usr' '--with-png-dir=/usr' '--enable-gd-native-ttf' '--with-openssl' '--with-fpm-user=nginx' '--with-fpm-group=nginx' '--with-libdir=lib64' '--enable-ftp' '--enable-opcache' '--enable-bcmath' '--enable-fpm' '--enable-mbstring'
make && make install
cp -f php.ini-production /opt/php56/lib/php.ini
upload_max_filesize=512M
post_max_size=512M
max_execution_time=300
max_input_time=300
for key in upload_max_filesize post_max_size max_execution_time max_input_time
do
 sed -i "s/^\($key\).*/\1 $(eval echo = \${$key})/" /opt/php56/lib/php.ini
done

cat > "/opt/php56/etc/php-fpm.conf" <<END
[global]
pid = run/php-fpm.pid
include=/opt/php56/etc/php-fpm.d/*.conf
END
mkdir -p /opt/php74/etc/php-fpm.d/ >/dev/null 2>&1
cat > "/lib/systemd/system/php-fpm-56.service" <<END
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target
[Service]
Type=simple
PIDFile=/opt/php56/var/run/php-fpm.pid
ExecStart=/opt/php56/sbin/php-fpm --nodaemonize --fpm-config /opt/php56/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true
[Install]
WantedBy=multi-user.target
END
}

