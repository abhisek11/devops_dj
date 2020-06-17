import xmltodict
import json
import zipfile
import gzip


def xml_to_json(file):
    if file.name.endswith('.xml'):
        _dict = xmltodict.parse(file.read())
        json_dump = json.dumps(_dict)
        return json_dump
    elif file.name.endswith('.zip'):
        zf = zipfile.ZipFile(file, 'r')
        for name in zf.namelist():
            _dict = xmltodict.parse(zf.open(name).read())
        json_dump = json.dumps(_dict)
        return json_dump
    elif file.name.endswith('.gz'):
        gz = gzip.open(file, 'r')
        _dict = xmltodict.parse(gz.read())
        json_dump = json.dumps(_dict)
        return json_dump
