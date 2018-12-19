
import requests
import json

api_key='AIzaSyCt5Gp1B8ZwzKtE9-2rb7dQk_KRkw4mNc4'

url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
payload = {'client': {'clientId': "mycompany", 'clientVersion': "0.1"},
           'threatInfo': {'threatTypes': ["SOCIAL_ENGINEERING", "MALWARE","UNWANTED_SOFTWARE","UNWANTED_SOFTWARE"],
                          'platformTypes': ["ANY_PLATFORM","ANDROID","LINUX","ALL_PLATFORMS"],
                          'threatEntryTypes': ["URL","IP_RANGE"],
                          'threatEntries': [{'url': "tuoitre.vn"}]}}
params = {'key': api_key}
r = requests.post(url, params=params, json=payload)
# Print response
print(r)
print(r.json())