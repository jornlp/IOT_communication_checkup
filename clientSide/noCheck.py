import requests

# request web page
resp = requests.get("http://example.com", verify=False)

# get the response text. in this case it is HTML
html = resp.text
print(html)