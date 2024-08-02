#!/usr/bin/env python
import requests
import os
import json
import csv
import jmespath
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
from box_sdk_gen import (
	BoxClient, BoxCCGAuth, CCGConfig, BoxAPIError,
	UploadFileAttributes, UploadFileAttributesParentField, PreflightFileUploadCheckParent,
	Files, File,
)
from _shared.functions import vault_call, qualys_call

#get qualys credentials from vault
vault_response_json = vault_call('wsaa/apiaccess/qualys')
qualys_un = json.dumps(vault_response_json["data"]["user"]).strip('\"')
qualys_pw = json.dumps(vault_response_json["data"]["password"]).strip('\"')

#get box credentials from vault
vault_response_json = vault_call('wsaa/apiaccess/Box')
box_client_id = json.dumps(vault_response_json["data"]["client-id"]).strip('\"')
box_client_secret = json.dumps(vault_response_json["data"]["client-secret"]).strip('\"')
box_enterprise_id = '83165'

ccg = CCGConfig(
    client_id=box_client_id,
    client_secret=box_client_secret,
    enterprise_id=box_enterprise_id,
)
auth = BoxCCGAuth(ccg)
client: BoxClient = BoxClient(auth=auth)

# get list of finished reports from Qualys
qualys_endpoint = '/api/2.0/fo/report/'
qualys_action = '?action=list&state=Finished'
qualys_response = qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_action)

# loop through reports
qualys_reponse_xml = ET.fromstring(qualys_response.text)
for elem in qualys_reponse_xml.findall('.//REPORT'):
	for child in elem:
		if(child.tag == 'ID'): report_id = child.text
		if(child.tag == 'TITLE'): report_title = child.text
		if(child.tag == 'LAUNCH_DATETIME'): 
			report_datetime = child.text.split('T')
			report_time = report_datetime[0].replace('-','')
		if(child.tag == 'OUTPUT_FORMAT'): report_format = child.text

	# fetch and save report to working directory
	qualys_report_action = '?action=fetch&id=' + report_id
	qualys_report_response = qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_report_action)

	report_file_name = report_title + '_' + report_time + '.' + report_format
	with open(report_file_name, "wb") as report:
		report.write(qualys_report_response.content)

	# upload to Box folder
	box_folder_id = '277885701226'
	file_path = report_file_name
	file_size = os.path.getsize(file_path)
	file_name = os.path.basename(file_path)
	file_id = None
	try:
		pre_flight_arg = PreflightFileUploadCheckParent(id=box_folder_id)
		client.uploads.preflight_file_upload_check(name=file_name, size=file_size, parent=pre_flight_arg)
	except BoxAPIError as err:
		if err.response_info.body.get("code", None) == "item_name_in_use":
			file_id = err.response_info.body["context_info"]["conflicts"]["id"]
		else:
			raise err
	upload_arg = UploadFileAttributes(file_name, UploadFileAttributesParentField(box_folder_id))
	if file_id is None:
		# upload new file
		files: Files = client.uploads.upload_file(upload_arg, file=open(file_path, "rb"))
	else:
		# upload new version
		files: Files = client.uploads.upload_file_version(file_id, upload_arg, file=open(file_path, "rb"))
	file = files.entries[0]
	print(f"File uploaded with id {file.id}, name {file.name}")

	# upload full CSV report to Cosmos DB
	if(report_title == 'WSAA_ALL_REP' and report_format == 'CSV'):
		# delete header lines
		with open(report_file_name, 'r') as fin:
			headers_orig = '"IP","DNS","NetBIOS","Tracking Method","OS","IP Status","QID","Title","Vuln Status","Type","Severity","Port","Protocol","FQDN","SSL","First Detected","Last Detected","Times Detected","Date Last Fixed","CVE ID","Vendor Reference","Bugtraq ID","CVSS","CVSS Base","CVSS Temporal","CVSS Environment","CVSS3.1","CVSS3.1 Base","CVSS3.1 Temporal","Threat","Impact","Solution","Exploitability","Associated Malware","Results","PCI Vuln","Ticket State","Instance","Category"'
			headers_new = headers_orig.lower().replace(' ','_').replace('"netbios"','"server"')
			data = fin.read().replace(headers_orig,headers_new).splitlines(True)
		with open(report_file_name, 'w') as fout:
			fout.writelines(data[10:])

		#get cosmos key from vault
		vault_response_json = vault_call('wsaa/apiaccess/cosmosdb')
		cosmos_key = json.dumps(vault_response_json["data"]["key"]).strip('\"')

		#connect to Cosmos DB
		from azure.cosmos import CosmosClient, PartitionKey, exceptions
		cosmos_url = 'https://mss-cosmos-customermanagement-account.documents.azure.com:443/'
		cosmos_client = CosmosClient(cosmos_url, credential=cosmos_key)
		database_name = 'mss-cosmos-customermanagement-db1'
		container_name = 'mss-qualys'
		database = cosmos_client.get_database_client(database_name)
		container_client = database.get_container_client(container_name)
		
		# ingest CSV file into JSON
		iter = 0
		data_dict = {}
		with open(report_file_name, encoding = 'utf-8') as csv_file_handler:
			csv_reader = csv.DictReader(csv_file_handler)
			for rows in csv_reader:
				iter += 1
				data_dict[iter] = rows

		# loop through JSON, insert to Cosmos DB
		iter = 0
		for key, subdict in data_dict.items():
			iter += 1
			subdict['id'] = report_file_name[13:19] + format(iter, '04')
			subdict['month'] = report_file_name[13:17] + '-' + report_file_name[17:19]
			container_client.upsert_item(subdict)
		print(str(iter) + ' Records inserted to ' + container_name)

	#delete file
	os.remove(report_file_name)