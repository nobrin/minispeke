# miniSPEKE service

This is a minimal SPEKE implementation.
This service will parse request XML and respond parameters.
Please attach lambda_handler for AWS Lambda and API Gateway HTTP V2.

## Usage
### API Service

This is for AWS Lambda and triggerd by API Gateway HTTP V2.
Set up services before use.

- Lambda
- API Gateway HTTP V2

While processing, secret key files will be stored into S3.
So the role needs permissions for put_obuject to S3.

Specify environment variables.

- SPK_S3_BUCKET -- S3 Bucket for storing secret key
- SPK_S3_PREFIX -- S3 Prefix for storing secret key
- SPK_PRESIGN_EXPIRES -- Valid seconds of pre-signed URL

This service store generated secret key for client into S3.
Object key of the secret key is s3://{S3_BUCKET}/{S3_PREFIX}/<ContentID>/<kid>.key

### Elemental MediaPackage

Set encryption parameters.
But, I'm not familiar with this service, so it may not be appropriate :-P

- DRM System ID -- 81376844-f976-481e-a84e-cc25d39b0b33
- URL -- https://APIGatewayID.execute-api.REGION.amazonaws.com/speke (for example)
- Encryption method -- AES 128-bit
- Constant IV -- Optional

You can use key rotation .

## Note

The SPEKE reference server ( https://github.com/awslabs/speke-reference-server )
uses the value 81376844-f976-481e-a84e-cc25d39b0b33 as System ID.
So, this follows that value, but it may be possible to generate.

