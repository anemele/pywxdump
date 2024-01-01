import json

init = './bias-data-init.json'
out = './bias-data.json'

with open(init, 'rb') as fp:
    data = json.load(fp)

data = {
    k: dict(name=v[0], account=v[1], phone=v[2], email=v[3], key=v[4])
    for k, v in data.items()
}

with open(out, 'w') as fp:
    json.dump(data, fp, indent=2)
