#curl -XGET https://safebrowsing.googleapis.com/v4/threatLists:list?key=my_api_key
#curl -XGET https://safebrowsing.googleapis.com/v4/threatLists:list?key=AIzaSyCt5Gp1B8ZwzKtE9-2rb7dQk_KRkw4mNc4
curl -H "Content-Type: application/json" \
-X POST -d '{
    "client": {
      "clientId":      "yourcompanyname",
      "clientVersion": "1.5.2"
    },
    "threatInfo": {
      "threatTypes":      ["MALWARE"],
      "platformTypes":    ["ANDROID"],
      "threatEntryTypes": ["URL","IP_RANGE"],
      "threatEntries": [
        {"url": "http://www.luckytime.co.kr"},
        {"url": "http://trafficconverter.biz:80"},
        {"url": "http://www.urltocheck3.com/"}
      ]
    }
  }' \
  https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyCt5Gp1B8ZwzKtE9-2rb7dQk_KRkw4mNc4