import requests
re = requests.get("http://" + self.ip + ":" + str(self.port) + "/336311a016184326ddbdd61edd4eeb52", timeout=5, headers=headers)
print(re.text)