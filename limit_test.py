import requests

URL = "http://localhost:5000/limit"

for i in range(10):
    r = requests.get(url = URL)
    data = r.json()
    print(data)