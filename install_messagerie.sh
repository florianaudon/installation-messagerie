#!/bin/bash
echo '
                        ____   ____ ____  ___ ____ _____ 
                       / ___| / ___|  _ \|_ _|  _ \_   _|
                       \___ \| |   | |_) || || |_) || |  
                        ___) | |___|  _ < | ||  __/ | |  
                       |____/ \____|_| \_\___|_|    |_|  
                                                         
           __  __ _____ ____ ____    _    ____ _____ ____  ___ _____ 
          |  \/  | ____/ ___/ ___|  / \  / ___| ____|  _ \|_ _| ____|
          | |\/| |  _| \___ \___ \ / _ \| |  _|  _| | |_) || ||  _|  
          | |  | | |___ ___) |__) / ___ \ |_| | |___|  _ < | || |___ 
          |_|  |_|_____|____/____/_/   \_\____|_____|_| \_\___|_____|
                                                                     

'

echo "Installation des dependances (mysql/apache/php/curl/dovecot/postfix/git)"

read -s -p "Mot de passe root sur MySQL: " PWD_ROOT_MYSQL

### Installation du serveur MySQL
if [[ ! -e /etc/init.d/mysql ]]; then
	echo "mysql-server-5.5 mysql-server/root_password password $PWD_ROOT_MYSQL" | debconf-set-selections #On evite que l'on demande un mot de passe pendant l'install
	echo "mysql-server-5.5 mysql-server/root_password_again password $PWD_ROOT_MYSQL" | debconf-set-selections
	apt-get  -y install mysql-server-5.5
fi

debconf-set-selections <<< "postfix postfix/mailname string $(hostname)"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

apt-get -y -q install  mysql-common php5-cgi php5-mcrypt php5-memcache php5-json php5-mysql php-gettext libapache2-mod-php5 curl dovecot-common dovecot-imapd dovecot-pop3d dovecot-mysql dovecot-managesieved postfix postfix-mysql git opendkim opendkim-tools




#            __     _____ __  __ ____    _    ____  __  __ ___ _   _ 
#            \ \   / /_ _|  \/  | __ )  / \  |  _ \|  \/  |_ _| \ | |
#             \ \ / / | || |\/| |  _ \ / _ \ | | | | |\/| || ||  \| |
#              \ V /  | || |  | | |_) / ___ \| |_| | |  | || || |\  |
#               \_/  |___|_|  |_|____/_/   \_\____/|_|  |_|___|_| \_|
#                                                                    

read -p "Voulez-vous configurer vimbadmin (y/n): " INSTALL_VIMBADMIN
if [[ $INSTALL_VIMBADMIN == "y"  ]]; then

read -e -p "Chemin d'installation: " INSTALL_PATH
if [[ ! -d $INSTALL_PATH ]]; then
	mkdir -p $INSTALL_PATH
	echo "dossier crée"
else
	INSTALL_PATH="$INSTALL_PATH/vimbadmin"
	echo "Chemin: $INSTALL_PATH"
	mkdir -p $INSTALL_PATH
fi

export INSTALL_PATH=$INSTALL_PATH
git clone https://github.com/opensolutions/ViMbAdmin.git $INSTALL_PATH
cd $INSTALL_PATH

### phpcomposer ###
if [[ ! -e $INSTALL_PATH/composer.phar  ]]; then
	echo "$INSTALL_PATH/composer.phar"
	curl -sS https://getcomposer.org/installer | php
	export COMPOSER_PROCESS_TIMEOUT=600  
	php composer.phar install --dev --verbose
fi

read -s -p "Mot de passe pour l'utilisateur ViMbAdmin sur MySQL: " PWD_VIMBADMIN_MYSQL

#Creation de la base
mysql -u root -p$PWD_ROOT_MYSQL -e "CREATE DATABASE \`vimbadmin\`;
GRANT ALL ON \`vimbadmin\`.* TO \`vimbadmin\`@\`localhost\` IDENTIFIED BY '$PWD_VIMBADMIN_MYSQL';
FLUSH PRIVILEGES;"

#configuration ViMbAdmin (/application/configs/application.ini)
cp $INSTALL_PATH/application/configs/application.ini.dist $INSTALL_PATH/application/configs/application.ini
sed -i "s/resources.doctrine2.connection.options.password = 'xxx'/resources.doctrine2.connection.options.password = '$PWD_VIMBADMIN_MYSQL'/g" $INSTALL_PATH/application/configs/application.ini

sed -i "s/defaults.mailbox.uid = 2000/defaults.mailbox.uid = 5000/g" $INSTALL_PATH/application/configs/application.ini
sed -i "s/defaults.mailbox.gid = 2000/defaults.mailbox.gid = 5000/g" $INSTALL_PATH/application/configs/application.ini
echo -e "\n"
read -e -p "Chemin vers vmail: " CHEMIN_VMAIL

sed -i "s#defaults.mailbox.maildir = \"maildir:/srv/vmail/%d/%u/mail:LAYOUT=fs\"#defaults.mailbox.maildir = \"maildir:$CHEMIN_VMAIL/%d/%u/mail:LAYOUT=fs\"/#" $INSTALL_PATH/application/configs/application.ini
sed -i "s#defaults.mailbox.homedir = \"/srv/vmail/%d/%u\"#defaults.mailbox.homedir = \"$CHEMIN_VMAIL/%d/%u\"#g" $INSTALL_PATH/application/configs/application.ini

sed -i "s/defaults.mailbox.password_scheme = \"md5.salted\"/defaults.mailbox.password_scheme = \"dovecot:SHA512-CRYPT\"/g" $INSTALL_PATH/application/configs/application.ini

sed -i "s/server.email.name = \"ViMbAdmin Administrator\"/server.email.name = \"Mail Administrator\"/g" $INSTALL_PATH/application/configs/application.ini
sed -i "s/server.email.address = \"support@example.com\"/server.email.address = \"network@newquest.fr\"/g" $INSTALL_PATH/application/configs/application.ini

cp $INSTALL_PATH/public/.htaccess.dist $INSTALL_PATH/public/.htaccess
./bin/doctrine2-cli.php orm:schema-tool:create

#Apache
chown -R www-data: $INSTALL_PATH
a2enmod rewrite
if [[ ! $(cat /etc/apache2/apache2.conf) =~ "vimbadmin" ]]; then 
echo "
        Alias /vimbadmin $INSTALL_PATH/public

        <Directory $INSTALL_PATH/public>
            Options FollowSymLinks
            AllowOverride None

            # For Apache <= 2.3:
            Order allow,deny
            allow from all

            # For Apache >= 2.4
            # Require all granted    

            SetEnv APPLICATION_ENV production

            RewriteEngine On
            RewriteCond %{REQUEST_FILENAME} -s [OR]
            RewriteCond %{REQUEST_FILENAME} -l [OR]
            RewriteCond %{REQUEST_FILENAME} -d
            RewriteRule ^.*$ - [NC,L]
            RewriteRule ^.*$ /vimbadmin/index.php [NC,L]
        </Directory>
	" >> /etc/apache2/apache2.conf #On fait en sorte que ce soit accessible via l'url http://xxxxx/vimbadmin
fi
service apache2 reload #On recharge apache pour prendre en compte les modifications

#echo "Connectez-vous sur vimbadmin en allant sur l'url http://xxxx/vimbadmin"
#read -p "securitysalt (sans les guillemets):" SECURITY_SALT
#read -p "resources.auth.oss.rememberme.salt (sans les guillemets):" REMEMBER_ME_SALT
#read -p "defaults.mailbox.password_salt (sans les guillemets):" PASSWORD_SALT
SETUP_WEB=$(curl $(hostname -I | sed 's/ //g')/vimbadmin -L -s )
SETUP_WEB=$(echo "$SETUP_WEB" | w3m -dump -T text/html) #On remplace les caractere html (&lt;,...)

#Remplacements des / qui perturbe le sed
SECURITY_SALT=$(echo -e "$SETUP_WEB" | grep securitysalt | cut -d\" -f 2 )
REMEMBER_ME_SALT=$(echo -e "$SETUP_WEB" | grep resources.auth.oss.rememberme.salt | cut -d\" -f 2 )
PASSWORD_SALT=$(echo -e "$SETUP_WEB" | grep defaults.mailbox.password_salt | cut -d\" -f 2 )


SECURITY_SALT=$(echo ${SECURITY_SALT:0:64}) #On decoupe car il faut une chaine de 65 caractere et des fois il retourne plus. Pourquoi?? Je sais pas!!
REMEMBER_ME_SALT=$(echo ${REMEMBER_ME_SALT:0:64})
PASSWORD_SALT=$(echo ${PASSWORD_SALT:0:64})


#On ecrit les salts dans le fichier de config
replace "securitysalt                       = \"\"" "securitysalt                       = \"$SECURITY_SALT\"" -- $INSTALL_PATH/application/configs/application.ini
replace "resources.auth.oss.rememberme.salt = \"\"" "resources.auth.oss.rememberme.salt = \"$REMEMBER_ME_SALT\"" -- $INSTALL_PATH/application/configs/application.ini
replace "defaults.mailbox.password_salt     = \"\"" "defaults.mailbox.password_salt     = \"$PASSWORD_SALT\"" -- $INSTALL_PATH/application/configs/application.ini

read -p "Login (email): " LOGIN
read -s -p "Mot de passe: " PASSWORD
#On fini d'activer le vimbadmin 
NULL=$(/usr/bin/curl --max-time 5 -s --data-urlencode "salt=$SECURITY_SALT" --data "username=$LOGIN&password=$PASSWORD" $(hostname -I | sed 's/ //g')/vimbadmin/auth/setup  -L 2>&1 /dev/null) #On fait -L pour suivre les redirection et on encode le salt pour eviter que les caracteres speciaux interferes dans la requete

fi

#                     ____   ___  ____ _____ _____ _____  __
#                    |  _ \ / _ \/ ___|_   _|  ___|_ _\ \/ /
#                    | |_) | | | \___ \ | | | |_   | | \  / 
#                    |  __/| |_| |___) || | |  _|  | | /  \ 
#                    |_|    \___/|____/ |_| |_|   |___/_/\_\
#                                                           

read -p "Voulez vous configurer postfix (y/n): " INSTALL_POSTFIX
if [[ $INSTALL_POSTFIX == "y"  ]]; then

groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d $CHEMIN_VMAIL -m

echo "
user = vimbadmin
password = $PWD_VIMBADMIN_MYSQL
hosts = 127.0.0.1
dbname = vimbadmin
query = SELECT goto FROM alias WHERE address = '%s' AND active = '1'
" > /etc/postfix/mysql-virtual-alias-maps.cf

echo "
user = vimbadmin
password = $PWD_VIMBADMIN_MYSQL
hosts = 127.0.0.1
dbname = vimbadmin
query = SELECT domain FROM domain WHERE domain = '%s' AND backupmx = '0' AND active = '1'
" > /etc/postfix/mysql-virtual-mailbox-domains.cf 

echo "
user = vimbadmin
password = $PWD_VIMBADMIN_MYSQL
hosts = 127.0.0.1
dbname = vimbadmin
table = mailbox
select_field = maildir
where_field = username
" > /etc/postfix/mysql-virtual-mailbox-maps.cf 

echo "
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_mailbox_base = /home/vmail
virtual_create_maildirsize = yes
virtual_maildir_extended = yes
virtual_transport=dovecot
dovecot_destination_recipient_limit=1

# Requirements for the HELO statement
smtpd_helo_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_non_fqdn_hostname,reject_invalid_hostname,permit
smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination,reject_non_fqdn_recipient,reject_unknown_sender_domain,reject_non_fqdn_sender,reject_unknown_recipient_domain,reject_invalid_helo_hostname,reject_unlisted_recipient,reject_unlisted_sender,reject_non_fqdn_helo_hostname,reject_rbl_client list.dsbl.org,reject_rhsbl_sender dsn.rfc-ignorant.org
smtpd_sender_restrictions=warn_if_reject reject_unverified_sender,permit_mynetworks,permit_sasl_authenticated,reject_non_fqdn_sender,reject_unknown_sender_domain,permit
" >> /etc/postfix/main.cf

read -p "Nom de domaine du serveur: " NOMDOMAIN

echo '
# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache

# SASL SMTPS
smtpd_sasl_type = dovecot
smtpd_sasl_auth_enable = yes
smtpd_sasl_path = private/auth
' >> /etc/postfix/main.cf

echo "
# Specify a list of properties separated by comma or whitespace
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = $NOMDOMAIN
" >> /etc/postfix/main.cf

replace "myhostname =" "#myhostname =" -- /etc/postfix/main.cf
echo "myhostname = $NOMDOMAIN" >> /etc/postfix/main.cf

#On decommente certaines lignes
replace "#smtp      inet  n       -       -       -       -       smtpd" "smtp      inet  n       -       -       -       -       smtpd" -- /etc/postfix/master.cf
replace "#submission inet n       -       -       -       -       smtpd" "submission inet n       -       -       -       -       smtpd" -- /etc/postfix/master.cf
replace "#  -o smtpd_tls_security_level=encrypt" "  -o smtpd_tls_security_level=encrypt" -- /etc/postfix/master.cf
replace "#  -o smtpd_sasl_auth_enable=yes" "  -o smtpd_sasl_auth_enable=yes" -- /etc/postfix/master.cf
replace "#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject" "  -o smtpd_client_restrictions=permit_sasl_authenticated,reject" -- /etc/postfix/master.cf
replace "#  -o milter_macro_daemon_name=ORIGINATING" "  -o milter_macro_daemon_name=ORIGINATING" -- /etc/postfix/master.cf
replace "#smtps     inet  n       -       -       -       -       smtpd" "smtps     inet  n       -       -       -       -       smtpd" -- /etc/postfix/master.cf
replace "#  -o smtpd_tls_wrappermode=yes" "  -o smtpd_tls_wrappermode=yes" -- /etc/postfix/master.cf
replace "#  -o smtpd_sasl_auth_enable=yes" "  -o smtpd_sasl_auth_enable=yes" -- /etc/postfix/master.cf
replace "#  -o smtpd_client_restrictions=permit_sasl_authenticated,reject" "  -o smtpd_client_restrictions=permit_sasl_authenticated,reject" -- /etc/postfix/master.cf

echo '
dovecot unix - n n - - pipe
 flags=DRhu user=vmail argv=/usr/lib/dovecot/deliver -d ${recipient}
'>> /etc/postfix/master.cf

fi
#                    ____   _____     _______ ____ ___ _____ 
#                   |  _ \ / _ \ \   / / ____/ ___/ _ \_   _|
#                   | | | | | | \ \ / /|  _|| |  | | | || |  
#                   | |_| | |_| |\ V / | |__| |__| |_| || |  
#                   |____/ \___/  \_/  |_____\____\___/ |_|  
#                                                            

read -p "Voulez-vous configurer dovecot (y/n): " INSTALL_DOVECOT
if [[ $INSTALL_DOVECOT == "y"  ]]; then

echo "
driver = mysql

connect = host=127.0.0.1 user=vimbadmin password=$PWD_VIMBADMIN_MYSQL dbname=vimbadmin
default_pass_scheme = SHA512-CRYPT
password_query = SELECT username as user, password FROM mailbox where username = \"%u\";
" > /etc/dovecot/dovecot-sql.conf

echo "
# OS: Linux 3.2.13-grsec-xxxx-grs-ipv6-64 x86_64
auth_mechanisms = plain login
mail_location = maildir:/home/vmail/%d/%n/Maildir
namespace inbox {
  inbox = yes
  location =
  mailbox Drafts {
    special_use = \Drafts
  }
  mailbox Junk {
    special_use = \Junk
  }
  mailbox Sent {
    special_use = \Sent
  }
  mailbox \"Sent Messages\" {
    special_use = \Sent
  }
  mailbox Trash {
    special_use = \Trash
  }
  prefix =
}
passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
plugin {
  sieve = ~/.dovecot.sieve
  sieve_dir = ~/sieve
}
protocols = imap pop3 sieve
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}
ssl_cert = </etc/dovecot/dovecot.pem
ssl_key = </etc/dovecot/private/dovecot.pem
userdb {
  args = uid=5000 gid=5000 home=/home/vmail/%d/%n
  driver = static
}

protocol lda {
        postmaster_address=$LOGIN
        mail_plugins = sieve
}

" >> /etc/dovecot/dovecot.conf

service dovecot restart
service postfix restart

fi
#             ____   ___  _   _ _   _ ____   ____ _   _ ____  _____ 
#            |  _ \ / _ \| | | | \ | |  _ \ / ___| | | | __ )| ____|
#            | |_) | | | | | | |  \| | | | | |   | | | |  _ \|  _|  
#            |  _ <| |_| | |_| | |\  | |_| | |___| |_| | |_) | |___ 
#            |_| \_\\___/ \___/|_| \_|____/ \____|\___/|____/|_____|
#                                                                   

read -p "Voulez vous configurer Roundcube (y/n): " INSTALL_ROUNDCUBE

if [[ $INSTALL_ROUNDCUBE == "y" ]]; then

cd /tmp
wget https://downloads.sourceforge.net/project/roundcubemail/roundcubemail/1.1.1/roundcubemail-1.1.1-complete.tar.gz
tar -xvf roundcubemail-1.1.1-complete.tar.gz
read -e -p "Repertoire ou je dois copier Roundcube: " INSTALL_PATH_ROUNDCUBE
 
if [[ ! -d $INSTALL_PATH_ROUNDCUBE ]]; then
	mkdir -p $INSTALL_PATH_ROUNDCUBE
	echo "dossier crée"
else
	INSTALL_PATH_ROUNDCUBE="$INSTALL_PATH_ROUNDCUBE/roundcube"
	echo "Chemin: $INSTALL_PATH_ROUNDCUBE"
	mkdir -p $INSTALL_PATH_ROUNCUBE
fi
cp roundcubemail-1.1.1/* $INSTALL_PATH_ROUNDCUBE/ -R

#Apache
chown -R www-data: $INSTALL_PATH_ROUNDCUBE
read -p "Nom du chemin pour l'accès web (http://webmail.fr/xxxx): " CHEMIN_APACHE_ROUNDCUBE

if [[ ! $(cat /etc/apache2/apache2.conf) =~ "###Roundcube###" ]]; then
echo "
	###Roundcube###
        Alias /$CHEMIN_APACHE_ROUNDCUBE $INSTALL_PATH_ROUNDCUBE

        <Directory $INSTALL_PATH_ROUNDCUBE>
            Options FollowSymLinks
            AllowOverride None

            # For Apache <= 2.3:
            Order allow,deny
            allow from all
            # For Apache >= 2.4
            # Require all granted    


        </Directory>
        " >> /etc/apache2/apache2.conf #On fait en sorte que ce soit accessible via l'url http://xxxxx/vimbadmin
fi
service apache2 reload #On recharge apache pour prendre en compte les modifications
read -p "Voulez vous que je configure roundcube (y/n)" CONF_ROUNDCUBE
if [[ $CONF_ROUNDCUBE == "y" ]]; then

	read -s -p "Mot de passe pour l'utilisateur Roundcube sur MySQL:" PWD_ROUNDCUBE_MYSQL
	#Creation de la base
	mysql -u root -p$PWD_ROOT_MYSQL -e "CREATE DATABASE \`roundcube\`;
	GRANT ALL ON \`roundcube\`.* TO \`roundcube\`@\`localhost\` IDENTIFIED BY '$PWD_ROUNDCUBE_MYSQL';
	FLUSH PRIVILEGES;"
       	
	cp $INSTALL_PATH_ROUNDCUBE/config/config.inc.php.sample $INSTALL_PATH_ROUNDCUBE/config/config.inc.php
	replace "$config['db_dsnw'] = 'mysql://roundcube:pass@localhost/roundcubemail';" "$config['db_dsnw'] = 'mysql://roundcube:$PWD_ROUNDCUBE_MYSQL@localhost/roundcube';" -- $INSTALL_PATH_ROUNDCUBE/config/config.inc.php
	echo "\$config['enable_installer'] = true;" >> $INSTALL_PATH_ROUNDCUBE/config/config.inc.php
	NULL=$(curl  $(hostname -I | sed 's/ //g')/$CHEMIN_APACHE_ROUNDCUBE/installer/index.php?_step=3 --data "initdb=Initialize+database&_from&_to&host=localhost&_user&_pass" -s) #On initialise la bdd
	replace "\$config['enable_installer'] = true;" ""  -- $INSTALL_PATH_ROUNDCUBE/config/config.inc.php

fi

#Sieve
read -p "Voulez vous installer le plugin managesieve de Roundcube (y/n): " INSTALL_MANAGESIEVE_ROUNDCUBE

if [[ $INSTALL_MANAGESIEVE_ROUNDCUBE == "y" ]]; then

	echo -e "array_push(\$config['plugins'],'managesieve'); \n" >> $INSTALL_PATH_ROUNDCUBE/config/config.inc.php
	cp $INSTALL_PATH_ROUNDCUBE/plugins/managesieve/config.inc.php.dist $INSTALL_PATH_ROUNDCUBE/plugins/managesieve/config.inc.php
fi
fi #fin du if d'install de roundcube

#                             ____  _  _____ __  __ 
#                            |  _ \| |/ /_ _|  \/  |
#                            | | | | ' / | || |\/| |
#                            | |_| | . \ | || |  | |
#                            |____/|_|\_\___|_|  |_|
#

read -p "Voulez vous configurer DKIM (y/n): " CONF_DKIM
if [[ $CONF_DKIM == "y" ]]; then

	read -p "Nom domaine DKIM: " DOMAINE_DKIM
	mkdir /etc/opendkim/
	echo "Domain                  $DOMAINE_DKIM" >> /etc/opendkim.conf
	echo "SigningTable       /etc/opendkim/SigningTable" >> /etc/opendkim.conf
	echo "KeyFile           /etc/opendkim/KeyFile" >> /etc/opendkim.conf
	echo "SOCKET                  inet:8891@localhost" >> /etc/opendkim.conf
	echo "Selector               mail" >> /etc/opendkim.conf

	echo "
# DKIM
#milter_default_action = accept
#milter_protocol = 2
#smtpd_milters = inet:localhost:8891
#non_smtpd_milters = inet:localhost:8891" >> /etc/postfix/main.cf
	
	read -p "Entrer tous les domaines séparé par un espace: " TOUS_DOMAINES_DKIM
	TOUS_DOMAINES_DKIM=$(echo $TOUS_DOMAINES_DKIM | tr " " "\n")
	while read DOMAINE
	do
		cd /etc/opendkim/
		opendkim-genkey -t -s mail -d $DOMAINE -b 2048
		mv mail.private $DOMAINE.key
		mv mail.txt $DOMAINE.dns
		echo "*@$DOMAINE:$DOMAINE:/etc/opendkim/$DOMAINE.key" >> /etc/opendkim/KeyFile
		echo "$DOMAINE default._domainkey.$DOMAINE" >> /etc/opendkim/SigningTable
		cat /etc/opendkim/$DOMAINE.dns

	done <<< "$TOUS_DOMAINES_DKIM"
	echo -e "
\e[0;31mOpenDKIM n'est pas activé, pour cela il faut:
	-Ajouter les valeurs precedentes dans la zone DNS
	-Decommenter la partie DKIM du fichier /etc/postfix/main.cf
	-Redemarrer postfix et openDKIM\e[0m"	
fi