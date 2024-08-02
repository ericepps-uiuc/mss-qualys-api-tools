#!/usr/bin/env python
import requests
import os
import json
import jmespath
from requests.auth import HTTPBasicAuth
from _shared.functions import vault_call, qualys_call

vault_response_json = vault_call('wsaa/apiaccess/qualys')
qualys_un = json.dumps(vault_response_json["data"]["user"]).strip('\"')
qualys_pw = json.dumps(vault_response_json["data"]["password"]).strip('\"')

vault_response_json = vault_call('wsaa/apiaccess/lansweeper')
lansweeper_api_token = json.dumps(vault_response_json["data"]["lansweeper_api_token"]).strip('\"')
lansweeper_site_id = json.dumps(vault_response_json["data"]["lansweeper_site_id"]).strip('\"')
lansweeper_url = 'https://api.lansweeper.com/api/v2/graphql'

lansweeper_headers = {
    'Authorization': lansweeper_api_token,
    'Content-Type': 'application/json',
}

lansweeper_query = """
query getAssetResources {{
          site(id: "{0}") {{
            assetResources(
              assetPagination:{{
                limit: 500,
              }},
              fields: [
                "assetBasicInfo.name"
                "assetBasicInfo.typeGroup"
                "assetBasicInfo.fqdn"
                "assetBasicInfo.ipAddress"
                "operatingSystem.name"
                "operatingSystem.version"
                "assetCustom.stateName"
                "assetGroups.assetGroupKey"
                "assetGroups.name"
                "assetCustom.manufacturer"
                "assetCustom.model"
              ]
                filters: {{
                conjunction: AND
                conditions: [
                  {{ operator: EQUAL, path: "assetCustom.stateName", value: "Active" }}
                ]
              }}
            ) {{
              total
              pagination {{
                limit
                current
                next
                page
              }}
              items
            }}
          }}
        }}
""".format(lansweeper_site_id)

lansweeper_response = requests.post(url=lansweeper_url, headers=lansweeper_headers, json={"query": lansweeper_query})
lansweeper_response_json = lansweeper_response.json()

assets_json = lansweeper_response_json["data"]["site"]["assetResources"]["items"]
asset_groups = jmespath.search('[*].assetGroups[0].name', assets_json)

def uniq_list(list):
    unique_list = []
    for x in list:
      if x not in  unique_list:
        unique_list.append(x)
    return unique_list

uniq_asset_groups = uniq_list(asset_groups)

##Asset Groups
ansible_inv_groups = {}
for asset_group in uniq_asset_groups:
  group = {asset_group: { "hosts": []}}
  query = "[?assetGroups[0].name=='{}'].assetBasicInfo.ipAddress".format(asset_group)
  host_list = jmespath.search(query, assets_json)
  group[asset_group]["hosts"] = host_list
  ansible_inv_groups.update(group)
#  #break

ansible_inv = ansible_inv_groups

# get list of asset groups from Qualys
qualys_endpoint = '/api/2.0/fo/asset/group/'
qualys_action = '?action=list&output_format=csv&show_attributes=ID,TITLE,IP_SET'
qualys_response = qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_action)

qualys_response_csv = qualys_response.content.splitlines()
qualys_response_row = list(qualys_response_csv)

# convert CSV response to json
qualys_groups = {}
for row in qualys_response_row:
	row_content = row.decode()
	row_groups = []
	if (row_content not in ['----BEGIN_RESPONSE_BODY_CSV','----END_RESPONSE_BODY_CSV','"ID","TITLE","IP_SET"']):
		row_groups.append(row_content.split('",'))

	for group_items in row_groups:
		group = {group_items[1].replace('"',''): {"id": group_items[0].replace('"',''), "ip-set": group_items[2].replace('"','')}}
		qualys_groups.update(group)

# get IP addresses from Lansweeper asset groups, update/create Qualys asset groups
ip_addresses_all = ''
for asset_group in uniq_asset_groups:
	print(asset_group)
	ip_addresses = ''

	for asset_group_ips in ansible_inv_groups[asset_group]["hosts"]:
		if(asset_group_ips not in ['192.17.95.159']):
			ip_addresses = ip_addresses + asset_group_ips + ','
			ip_addresses_all = ip_addresses_all + asset_group_ips + ','

	if (asset_group + '_IP' in json.dumps(qualys_groups)):
		qualys_action = '?action=edit&set_ips=' + ip_addresses + '&id=' + qualys_groups[asset_group + '_IP']['id']
	else:
		qualys_action = '?action=add&ips=' + ip_addresses + '&title=' + asset_group + '_IP'

	qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_action)

# update all asset group
print('WSAA_ALL')
qualys_action = '?action=edit&set_ips=' + ip_addresses_all + '&id=10320182'
qualys_call(qualys_un, qualys_pw, qualys_endpoint, qualys_action)

