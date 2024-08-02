#!/usr/bin/env python
import requests
import os
import json
import jmespath
from requests.auth import HTTPBasicAuth
import xml.etree.ElementTree as ET
from box_sdk_gen import (
	BoxClient, BoxCCGAuth, CCGConfig, BoxAPIError,
	UploadFileAttributes, UploadFileAttributesParentField, PreflightFileUploadCheckParent,
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

# get list of finished reports from Qualys
qualys_endpoint = '/api/2.0/fo/report/'
qualys_action = '?action=list&state=Finished'
qualys_response = qualys_call(qualys_endpoint, qualys_action)

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
	qualys_report_response = qualys_call(qualys_endpoint, qualys_report_action)

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
	
	#delete file
	os.remove(report_file_name)