# Qualys API Tools

Lansweeper inventory based on https://github.com/techservicesillinois/mss-ansible-lansweeper-inventory/

qualys_asset_groups.py gathers ip addresses by asset group from Lansweeper and creates/updates asset groups in Qualys

qualys_reports.py downloads all finished reports and then uploads them to a Box folder using Box SDK (https://github.com/box/box-python-sdk-gen)

ansible-playbook awx_config.yml to add job templates, etc., to AWX
