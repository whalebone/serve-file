# README

# Build
En example, by all means use your own tags:
```
docker build -t karm/serve-file:1.0.0 . && docker push karm/serve-file:1.0.0
```
TODO: tie Docker tag to build version and bake it into the binary for logging and audit.

# Basic usage
```
docker run \
 -e SRV_NUM_OF_CPUS=2 \
 -e SRV_CA_CERT_PEM_BASE64=`base64 -w0 certs/ca/certs/ca-chain.cert.pem` \
 -e SRV_SERVER_CERT_PEM_BASE64=`base64 -w0 certs/server/certs/server.cert.pem` \
 -e SRV_SERVER_KEY_PEM_BASE64=`base64 -w0 certs/server/private/server.key.nopass.pem` \
 -e SRV_BIND_PORT="8443" -e SRV_BIND_HOST="0.0.0.0" \
 -e SRV_API_URL="/sinkit/rest/protostream/resolvercache/" \
 -e SRV_API_FILE_DIR="/test-data" \
 -p 127.0.0.1:8443:8443/tcp \
 -v /home/karm/Projects/rob/serve-file/test-data/:/test-data/:ro -d -i \
 --name serve-file karm/serve-file:1.0.0
```
```
curl https://localhost:8443/sinkit/rest/protostream/resolvercache/ \
 "-Hx-resolver-id: 404" --cert certs/client/certs/client-404.cert.pem \
 --key certs/client/private/client-404.key.nopass.pem --cacert certs/ca/certs/ca-chain.cert.pem -I

 HTTP/1.1 200 OK
 Accept-Ranges: bytes
 Content-Length: 404
 Content-Type: application/octet-stream
 Etag: "ce1ac9c4f8ac7a1807253d015ccd40d5"
 Last-Modified: Thu, 25 Oct 2018 10:42:46 GMT
 Strict-Transport-Security: max-age=63072000; includeSubDomains
 Date: Tue, 30 Oct 2018 11:47:05 GMT
```
```
curl https://localhost:8443/sinkit/rest/protostream/resolvercache/ \
 "-Hx-resolver-id: 404" "-HIf-None-Match: \"ce1ac9c4f8ac7a1807253d015ccd40d5\"" \
 --cert certs/client/certs/client-404.cert.pem --key certs/client/private/client-404.key.nopass.pem \
 --cacert certs/ca/certs/ca-chain.cert.pem -I

HTTP/1.1 304 Not Modified
Etag: "ce1ac9c4f8ac7a1807253d015ccd40d5"
Strict-Transport-Security: max-age=63072000; includeSubDomains
Date: Tue, 30 Oct 2018 11:48:26 GMT
```
