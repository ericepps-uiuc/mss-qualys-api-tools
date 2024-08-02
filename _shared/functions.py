#!/usr/bin/env python
import requests
import os
from requests.auth import HTTPBasicAuth

def qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_action):
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

def vault_call(vault_path):
	vault_url = 'https://smg-vault.techservices.illinois.edu:8200/v1/' + vault_path
	vault_token = os.environ["VAULT_TOKEN"]
	headers = {'X-Vault-Token': vault_token}

	vault_response = requests.get(vault_url, headers=headers)
	vault_response_json = vault_response.json()
	return vault_response_json