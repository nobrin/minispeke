#!/usr/bin/env python3
"""
Simple SPEKE response service

This service will parse request XML and respond parameters.
Please attach lambda_handler for AWS Lambda and API Gateway HTTP V2.
"""
import os, json, secrets
from base64 import b64decode, b64encode
from xml.dom.minidom import parseString
from hashlib import md5
import boto3

__author__ = "Nobuo Okazaki"
__version__ = "0.0.1"
__license__ = "MIT"

S3_BUCKET = os.environ["SPK_S3_BUCKET"]
S3_PREFIX = os.environ["SPK_S3_PREFIX"]
PRESIGN_EXPIRES = os.environ.get("SPK_PRESIGN_EXPIRES", 70)

# Set secret bytestring for generating secret key
# It is better to change the value for security.
# For example, this is b64encoded 64 bytes randam bytes.
B64SECRET = "uyzjfRCgCmV+lFmigoE+MwvDCmZvx+R4RDHavbygwURP1u5J5FpEsnV8QKch5R73jTS24tq1Xupk8AOj9WQgog=="
SECRET_BYTES = b64decode(B64SECRET)

# This value was used in the SPEKE reference server.
# https://github.com/awslabs/speke-reference-server/blob/master/src/key_server_common.py
# Please change if you need
# These values should be avoided: https://dashif.org/identifiers/content_protection/
HLS_AES_128_SYSTEM_ID = "81376844-f976-481e-a84e-cc25d39b0b33"

def _b64(s):
    return b64encode(s.encode() if isinstance(s, str) else s).decode()

class SpekeDoc:
    # Support single ContentKey and single DRMSystem only
    def __init__(self, xml):
        xml = "".join([x.strip() for x in xml.split("\n")]) # Strip white spaces
        self.doc = parseString(xml)

        # Get parameters from the document
        self.kid = self.doc.getElementsByTagName("cpix:ContentKey")[0].getAttribute("kid")
        self.content_id = self.doc.documentElement.getAttribute("id")
        self.system_id = self.doc.getElementsByTagName("cpix:DRMSystem")[0].getAttribute("systemId")

    def fill_content_keys(self, key):
        # Fill parameters on the ContentKeyList
        elList = self.doc.getElementsByTagName("cpix:ContentKeyList")[0]
        for el in elList.getElementsByTagName("cpix:ContentKey"):
            el.setAttribute("explicitIV", _b64(key.iv))
            elData = self.doc.createElement("cpix:Data")
            elSec = self.doc.createElement("pskc:Secret")
            elValue = self.doc.createElement("pskc:PlainValue")
            elValue.appendChild(self.doc.createTextNode(_b64(key.key)))
            elSec.appendChild(elValue)
            elData.appendChild(elSec)
            el.appendChild(elData)

    def fill_drm_systems(self, key, keyurl):
        # Fill parameters on the DRMSystemList
        elList = self.doc.getElementsByTagName("cpix:DRMSystemList")[0]
        for el in elList.getElementsByTagName("cpix:DRMSystem"):
            self.set_value(el, "cpix:URIExtXKey", _b64(keyurl))
            self.set_value(el, "speke:KeyFormat", _b64(key.KEY_FORMAT))
            self.set_value(el, "speke:KeyFormatVersions", _b64(key.KEY_FORMAT_VERSION))

    def set_value(self, el, tag_name, value):
        # Set textNode
        text_node = self.doc.createTextNode(value)
        el.getElementsByTagName(tag_name)[0].appendChild(text_node)

    def to_xml(self, pretty=False):
        if pretty:
            return self.doc.toprettyxml(indent="  ")
        return self.doc.toxml()

class SpekeKey:
    KEY_FORMAT = "identity"
    KEY_FORMAT_VERSION = "1"

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    @classmethod
    def generate(cls, plain_text):
        # Generate secret key and initialization vector
        # Secret key will be generate from plain_text
        key = md5(plain_text).digest()  # 16bytes
        iv = secrets.token_bytes(16)
        return cls(key, iv)

s3 = boto3.client("s3")

def lambda_handler(evt, ctx):
    if "body" not in evt:
        return "OK"

    # Read body and decode if needed
    xml = b64decode(evt["body"]) if evt.get("isBase64Encoded") else evt["body"]
    if isinstance(xml, bytes): xml = xml.decode()

    # Parse request XML
    doc = SpekeDoc(xml)

    # Verify System ID
    if doc.system_id != HLS_AES_128_SYSTEM_ID:
        return {
            "isBase64Encoded": False,
            "statusCode": 400,
            "body": json.dumps({"message": "Invalid System ID"}),
            "headers": {"content-type": "application/json"},
        }

    # Generate secret key with ContentID, kid, and SECRET_BYTES
    # Store the key to s3://{S3_BUCKET}/{S3_PREFIX}/<ContentID>/<kid>.key
    # Generate pre-signed URL of the key file for the user
    key = SpekeKey.generate(f"{doc.content_id}:{doc.kid}:".encode() + SECRET_BYTES)
    object_key = f"{S3_PREFIX}/{doc.content_id}/{doc.kid}.key"
    s3.put_object(Bucket=S3_BUCKET, Key=object_key, Body=key.key)
    signed_url = s3.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": S3_BUCKET, "Key": object_key},
        ExpiresIn=PRESIGN_EXPIRES,
    )

    # Process the request XML and fill parameters on it
    doc.fill_content_keys(key)
    doc.fill_drm_systems(key, signed_url)

    return {
        "isBase64Encoded": False,
        "statusCode": 200,
        "body": doc.to_xml(),
        "headers": {"content-type": "application/xml"},
    }

if __name__ == "__main__":
    xml = open("sample-mediapackage-request.xml").read()
    evt = {
        "isBase64Encoded": False,
        "body": xml,
    }
    print(lambda_handler(evt, None))
