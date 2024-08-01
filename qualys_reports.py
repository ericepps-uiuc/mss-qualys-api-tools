#!/usr/bin/env python
import requests
import os
import json
import jmespath
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
from box_sdk_gen import (
	BoxClient, BoxDeveloperTokenAuth,
    UploadFileAttributes, UploadFileAttributesParentField,
    Files, File,
)

#get qualys credentials from vault
vault_url = 'https://smg-vault.techservices.illinois.edu:8200/v1/wsaa/apiaccess/qualys'
vault_token = os.environ["VAULT_TOKEN"]
headers = {'X-Vault-Token': vault_token}

vault_response = requests.get(vault_url, headers=headers)
vault_response_json = vault_response.json()

qualys_un = json.dumps(vault_response_json["data"]["user"]).strip('\"')
qualys_pw = json.dumps(vault_response_json["data"]["password"]).strip('\"')

#get box credentials from vault
vault_url = 'https://smg-vault.techservices.illinois.edu:8200/v1/wsaa/apiaccess/Box'
vault_token = os.environ["VAULT_TOKEN"]
headers = {'X-Vault-Token': vault_token}

vault_response = requests.get(vault_url, headers=headers)
vault_response_json = vault_response.json()

box_token = json.dumps(vault_response_json["data"]["dev-token"]).strip('\"')
#box_id = json.dumps(vault_response_json["data"]["client-id"]).strip('\"')
#box_secret = json.dumps(vault_response_json["data"]["client-secret"]).strip('\"')

auth: BoxDeveloperTokenAuth = BoxDeveloperTokenAuth(token=box_token)
client: BoxClient = BoxClient(auth=auth)

def qualys_call(qualys_endpoint, qualys_action):
	global qualys_un
	global qualys_pw
	qualys_auth = HTTPBasicAuth(qualys_un, qualys_pw)

	qualys_base_url = 'https://qualysapi.qualys.com'
	qualys_headers = {
	    'X-Requested-With': 'qualys_asset_groups.py',
	}
	qualys_url = qualys_base_url + qualys_endpoint + '' + qualys_action
	print(qualys_url)
	qualys_response = requests.post(url=qualys_url, headers=qualys_headers, auth=qualys_auth)
	print(qualys_response)
	return qualys_response

# get list of asset groups from Qualys
qualys_endpoint = '/api/2.0/fo/report/'
qualys_action = '?action=list&state=Finished'
qualys_response = qualys_call(qualys_endpoint, qualys_action)

# parse xml response
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
	qualys_report_response = qualys_call(qualys_endpoint, qualys_report_action)

	report_file_name = report_title + '_' + report_time + '.' + report_format
	with open(report_file_name, "wb") as report:
		report.write(qualys_report_response.content)

	# upload to Box folder
	attrs = UploadFileAttributes(
    	name=report_file_name, parent=UploadFileAttributesParentField(id="277885701226")
	)
	files: Files = client.uploads.upload_file(
    	attributes=attrs, file=open(report_file_name, "rb")
	)
	file: File = files.entries[0]
	print(f"File uploaded with id {file.id}, name {file.name}")


