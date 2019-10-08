#! /usr/bin/python

import sys
import os
import MySQLdb
import datetime
import time
from datetime import datetime, timedelta
import shutil
import json
import xml.etree.ElementTree as ET
import re
#Retrieve Arg (1 = filename, 2= tabName)
#FILE CREATED BY GETTING THE CONF OVER SSH (show conf) 

filename = sys.argv[1]
# tabName = sys.argv[2]

#GetGlobalValue (id scan, date import...)
#date 
now = datetime.now()
date_import = now.strftime("%Y-%m-%d")

# Open the workbook and define the worksheet
# book = xlrd.open_workbook(filename)
# sheet = book.sheet_by_name(tabName)

# Establish a MySQL connection
database = MySQLdb.connect (host="XXXXX", user = "XXXX", passwd = "XXXXXXX", db = "XXXXXX")

# Get the cursor, which is used to traverse the database, line by line
cursor = database.cursor()

tree = ET.parse(filename)
root = tree.getroot()
# conf = root.getchildren()
hostnameTab = []
for hostName in root.findall('configuration/groups/system/host-name'):
	hostnameTab.append(hostName.text)

#DATA HISTO
print ("Historisation des donnees du dernier import stonesoft")
try:
	values=('junos',hostnameTab[0])
	print(values)
	query = """INSERT INTO `firewall_flow_matrix_histo`(`id`, `key_rule`, `id_import`, `firewall_name`, `type_fw`, `safe`, `new`, `source`, `dest`, `protocole_port`, `comment`, `action`, `log_level`, `rule_number`, `dest_zone`, `target_zone`, `rule_status`, `obso_counter`, `ref`) SELECT * FROM `firewall_flow_matrix` WHERE type_fw = %s and firewall_name = %s """
	cursor.execute(query,values)

	cursor.close()
	database.commit()	
	print ("Historisation of data succeed")
except Exception as e:
	print ('Historisation of Stonesoft data FAILED '+str(e))
	sys.exit(1)
###PURGE DES DONNEES
cursor = database.cursor()		
try:
	print ("Debut de la purge...")
	values=('junos',hostnameTab[0])
	query = """DELETE FROM `firewall_flow_matrix` WHERE type_fw = %s and firewall_name =  %s """
	cursor.execute(query,values)
	# cursor.execute("DELETE FROM `firewall_flow_matrix` WHERE type_fw = 'junos'")
	cursor.close()
	database.commit()	
	print ("Purge of data succeed")
except Exception as e:
	print("Purge of firewall_flow_matrix data FAILED "+str(e))
	cursor.close()
	sys.exit(1)

cursor = database.cursor()
# Get Imports IDs
id_import = 0
values = ('junos',hostnameTab[0])
query = """ select max(id_import) from `firewall_flow_matrix_histo` WHERE type_fw = %s and firewall_name = %s """
cursor.execute(query,values)
try:
	results = cursor.fetchone()
	for row in results:
		id_last_batch_tmp = row
		if str(id_last_batch_tmp) == 'None':
			id_last_batch=0
		else:
			id_last_batch = id_last_batch_tmp
except:
	id_last_batch = 0
id_import = id_last_batch+1


for policies in root.findall('configuration/security/policies/policy'):
	for policy in policies.findall('policy'):
		sourceTmp = '';
		destinationTmp = ''
		protocoleTmp = ''
		name = policy.find('name').text
		for src in policy.findall('match/source-address'):
			sourceTmp = sourceTmp + src.text+'---'
		for dest in policy.findall('match/destination-address'):
			destinationTmp = destinationTmp + dest.text+'---'
		for proto in policy.findall('match/application') : 
			protocoleTmp = protocoleTmp  + proto.text.replace('_',' ')+'---' 
		# print(str(name)+','+str(source)+','+str(destination)+','+str(protocole)+'_')
		try:
			rule_number = int(name)
		except:
			rule_number = '0'
		
		source=re.sub('---$','',sourceTmp)
		destination=re.sub('---$','',destinationTmp)
		protocole=re.sub('---$','',protocoleTmp)
		key_rule = str(rule_number)+'_'+source+'_'+destination+'_'+protocole
		
		actionTag = policy.find('then')
		if actionTag is None:
			action = ''
		else:
			action = actionTag[0].tag
		
		log_levelTag = policy.find('then/log')
		if log_levelTag is None:
			log_level = ''
		else:
			log_level = log_levelTag[0].tag

		values = (key_rule,id_import,hostnameTab[0],'junos','No','unchanged',source,destination,protocole,name,action,log_level,rule_number,'','','','0','')
		query = """INSERT INTO `firewall_flow_matrix`(`id`,`key_rule`,`id_import`,`firewall_name`, `type_fw`,`safe`,`new`, `source`, `dest`, `protocole_port`, `comment`, `action`, `log_level`, `rule_number`, `dest_zone`, `target_zone`, `rule_status`, `obso_counter`, `ref` ) VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s , %s,%s, %s,%s)"""
		cursor.execute(query,values)
		# print(str(values))
# f.close()
# Close the cursor
cursor.close()
# Commit the transaction
database.commit()
cursor = database.cursor()		
for globalpolicies in root.findall('configuration/security/policies/global'):
	for policy in globalpolicies.findall('policy'):
		sourceTmp = '';
		destinationTmp = ''
		protocoleTmp = ''
		name = policy.find('name').text
		for src in policy.findall('match/source-address'):
			sourceTmp = sourceTmp + src.text+'---'
		for dest in policy.findall('match/destination-address'):
			destinationTmp = destinationTmp + dest.text+'---'
		for proto in policy.findall('match/application') : 
			protocoleTmp = protocoleTmp  + proto.text.replace('_',' ')+'---' 
		# print(str(name)+','+str(source)+','+str(destination)+','+str(protocole)+'_')
		try:
			rule_number = int(name)
		except:
			rule_number = '0'
		
		source=re.sub('---$','',sourceTmp)
		destination=re.sub('---$','',destinationTmp)
		protocole=re.sub('---$','',protocoleTmp)
		key_rule = str(rule_number)+'_'+source+'_'+destination+'_'+protocole
		
		actionTag = policy.find('then')
		if actionTag is None:
			action = ''
		else:
			action = actionTag[0].tag
		
		log_levelTag = policy.find('then/log')
		if log_levelTag is None:
			log_level = ''
		else:
			log_level = log_levelTag[0].tag

		values = (key_rule,id_import,hostnameTab[0],'junos','No','unchanged',source,destination,protocole,name,action,log_level,rule_number,'','','','0','')
		query = """INSERT INTO `firewall_flow_matrix`(`id`,`key_rule`,`id_import`,`firewall_name`, `type_fw`,`safe`,`new`, `source`, `dest`, `protocole_port`, `comment`, `action`, `log_level`, `rule_number`, `dest_zone`, `target_zone`, `rule_status`, `obso_counter`, `ref` ) VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s , %s,%s, %s,%s)"""
		cursor.execute(query,values)
		# print(str(values))		
		
# for globalpolicies in root.findall('configuration/security/policies/global/policy'):
	# print globalpolicies.find('name').text
# f.close()
# Close the cursor
cursor.close()
# Commit the transaction
database.commit()

##Check des nouvelles rules ou des modifications
#NEW
try:
	cursor = database.cursor()
	query = """UPDATE firewall_flow_matrix set new='new' where type_fw = %s and id_import = %s and rule_number not in (select distinct rule_number from firewall_flow_matrix_histo where type_fw = %s and id_import = %s ) """
	values = ('junos',id_import, 'junos' , id_last_batch)
	cursor.execute(query, values)
	database.commit()
	print("CHECK NEW RULES OK " )
except Exception as e:
	print("Check des nouvelles regles FAILED "+str(e))
	cursor.close()
	sys.exit(1)
	
#MODIF
try:
	cursor = database.cursor()
	query = """UPDATE firewall_flow_matrix set new='modified' where type_fw = %s and id_import = %s and rule_number in (select distinct rule_number from firewall_flow_matrix_histo where type_fw = %s and id_import = %s ) and key_rule not in (select distinct key_rule from firewall_flow_matrix_histo where type_fw = %s and id_import = %s) """
	values = ('junos',id_import, 'junos' , id_last_batch, 'junos' , id_last_batch)
	cursor.execute(query, values)
	database.commit()
except Exception as e:
	print("Check des modifications sur regles FAILED "+str(e))
	cursor.close()
	sys.exit(1)
	
##Passage en Await Recertif des besoins ayant des regles modifiees
try:
	cursor = database.cursor()
	query = """UPDATE flow_approval set validated='Awaiting Recertification' where need_ref in (select idNeed from firewall_needs_flow fnf join firewall_flow_matrix ffm on fnf.key_rule = ffm.key_rule where ffm.new = 'modified')"""
	values = ''
	cursor.execute(query, values)
	database.commit()
	print("Update des rules a recertifier FAILED "+str(e))
except Exception as e:
	cursor.close()
	sys.exit(1)



# Close the database connection
database.close()



# Print results
print ""
print "All Done!"
print ""
