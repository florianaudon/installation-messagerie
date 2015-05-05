#!/bin/bash
#	read -e -p "Chemin d'installation de vimbadmin: " INSTALL_PATH	
fusionner_domaines(){
	while read DOMAIN
	do
		read -p "Souhaitez-vous activer le domaine $DOMAIN? (0/1)" ACTIVE </dev/tty 
		if [[ $ACTIVE != "1" && $ACTIVE != "2" ]]; then 
			ACTIVE=0
		 fi
		echo "INSERT INTO domain (domain,transport,created,active) VALUES ('$DOMAIN','virtual',NOW(),'$ACTIVE');" | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin

	done <<< "$(echo "SELECT domain FROM virtual_mailbox_domains;" | mysql -u $db_user -p$db_password $db_name | sed '1d')" #On supprime la premiere ligne pour eviter d'afficher et de prendre en compte le nom de la colonne
}
fusionner_mails(){

	while read MAIL PASSWORD
	do
		NAME=$(echo $MAIL | cut -d"@" -f 1)
		DOMAIN=$(echo $MAIL | cut -d"@" -f 2)
		DOMAIN_ID=$(echo "SELECT id FROM domain WHERE domain='$DOMAIN';" | mysql -u $db_user -p$db_password vimbadmin | sed '1d')
		echo "INSERT INTO mailbox (username,password,name,active,homedir,maildir,uid,gid,delete_pending,created,Domain_id) VALUES ('$MAIL','$PASSWORD','$NAME','1','$CHEMIN_VMAIL/$DOMAIN/$NAME','maildir:$CHEMIN_VMAIL/$DOMAIN/$NAME/mail:LAYOUT=fs/','5000','5000','0',NOW(),'$DOMAIN_ID');" | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin

		#Update nombre d'adresse mail
		MAILBOX_COUNT=$(echo "SELECT mailbox_count FROM domain where domain='$DOMAIN';" | mysql -u $db_user -p$db_password vimbadmin | sed '1d')
		echo "UPDATE domain SET mailbox_count=$((MAILBOX_COUNT+1)) WHERE domain='$DOMAIN'" | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin
		echo "INSERT INTO alias (address,goto,active,created,Domain_id) VALUES ('$MAIL','$MAIL','1',NOW(),'$DOMAIN_ID');" | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin
		
		unset MAILBOX_COUNT
	done <<< "$(echo "SELECT email,password FROM virtual_mailbox_maps;" | mysql -u $db_user -p$db_password $db_name | sed '1d' )"
}

fusionner_alias(){

	while read SOURCE DESTINATION
	do
		DOMAIN=$(echo $SOURCE | cut -d"@" -f 2)
		DOMAIN_ID=$(echo "SELECT id FROM domain WHERE domain='$DOMAIN';" | mysql -u $db_user -p$db_password vimbadmin | sed '1d')
		echo "INSERT INTO alias (address,goto,active,created,Domain_id) VALUES ('$SOURCE','$DESTINATION','1',NOW(),'$DOMAIN_ID');"  | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin

		ALIAS_COUNT=$(echo "SELECT alias_count FROM domain where domain='$DOMAIN';" | mysql -u $db_user -p$db_password vimbadmin | sed '1d')
		echo "UPDATE domain SET alias_count=$((ALIAS_COUNT+1)) WHERE domain='$DOMAIN'" | mysql -u vimbadmin -p$PWD_VIMBADMIN_MYSQL vimbadmin
		echo $SOURCE "--"$DESTINATION		
		unset ALIAS_COUNT
	done <<< "$(echo "SELECT source,destination FROM virtual_alias_maps;" | mysql -u $db_user -p$db_password $db_name | sed '1d' )"
}
#	replace "default_pass_scheme = SHA512-CRYPT" "default_pass_scheme = dovecot:crypt" -- /etc/dovecot/dovecot-sql.conf
#	replace "defaults.mailbox.password_scheme = \"md5.salted\"" "defaults.mailbox.password_scheme = \"dovecot:crypt\"" $INSTALL_PATH/application/configs/application.ini

read -e -p "Chemin du fichiers settings_postfix.sh: " SETTING_POSTFIX
read -s -p "Mot de passe pour l'utilisateur ViMbAdmin sur MySQL: " PWD_VIMBADMIN_MYSQL
echo -e "\n"
read -e -p "Chemin vers vmail: " CHEMIN_VMAIL
source $SETTING_POSTFIX

fusionner_domaines()
fusionner_mails()
fusionner_alias()

echo "Veuillez faire les modifications suviantes:
application/configs/application.ini de vimbadmin:
	defaults.mailbox.password_scheme = \"dovecot:crypt\"
/etc/postfix/mysql-virtual-alias-maps.cf 
	user = vimbadmin
	password = $PWD_VIMBADMIN_MYSQL
	hosts = 127.0.0.1
	dbname = vimbadmin
	query = SELECT goto FROM alias WHERE address = '%s' AND active = '1'		

/etc/postfix/mysql-virtual-mailbox-domains.cf 
	user = vimbadmin
	password = $PWD_VIMBADMIN_MYSQL
	hosts = 127.0.0.1
	dbname = vimbadmin
	query = SELECT domain FROM domain WHERE domain = '%s' AND backupmx = '0' AND active = '1'

/etc/postfix/mysql-virtual-mailbox-maps.cf 
	user = vimbadmin
	password = $PWD_VIMBADMIN_MYSQL
	hosts = 127.0.0.1
	dbname = vimbadmin
	table = mailbox
	select_field = maildir
	where_field = username

/etc/dovecot/dovecot-sql.conf
	driver = mysql
	connect = host=127.0.0.1 user=vimbadmin password=dzaBv8712rv dbname=vimbadmin
	default_pass_scheme = CRYPT
	password_query = SELECT username as user, password FROM mailbox where username = "%u";
"
