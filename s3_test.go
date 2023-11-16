/*
Copyright (C) 2018  Michal Karm Babacek

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	minioClient "github.com/minio/minio-go"
	"github.com/stretchr/testify/assert"
	"whalebone.io/serve-file/config"
)

/*
We run Minio server to mimic S3 endpoint for local testing.
*/
const (
	testEndpoint   = "localhost:9000"
	testBucketName = "serve-file"
	contentType    = "application/octet-stream"
	// Note if you change these properties below, you also have to update:
	// test-data/minio-data/.minio.sys/config/config.json
	testAccessKeyID          = "minio"
	testSecretAccessKey      = "minio123"
	testRegion               = "eu-west-1"
	testCloudCustomerID      = "1000042"
	testCloudEndpoint        = "localhost:19000"
	testCloudBucketName      = "serve-file-cloud"
	testCloudAccessKeyID     = "minio-cloud"
	testCloudSecretAccessKey = "minio-cloud123"
	testCloudRegion          = "eu-east-5"
	testCloudResolverID      = "10001"

	cloudResolverCert = "certs/client/certs/client-10001.cert.pem" // location 1000042 (client id)
	cloudResolverKey  = "certs/client/private/client-10001.key.nopass.pem"
)

var args = []string{
	"minio",
	"--config-dir", "test-data/minio-conf",
	"server",
	"--address", testEndpoint,
	"test-data/minio-data",
}

func uploadResolverFiles(dataFiles []string) {
	s3Client, err := minioClient.NewWithRegion(testEndpoint, testAccessKeyID, testSecretAccessKey, false, testRegion)
	if err != nil {
		log.Fatal(err)
	}
	uploadS3Files(dataFiles, s3Client, testBucketName)
}

func uploadCloudResolverFiles(dataFiles []string) {
	s3Client, err := minioClient.NewWithRegion(testCloudEndpoint, testCloudAccessKeyID, testCloudSecretAccessKey, false, testCloudRegion)
	if err != nil {
		log.Fatal(err)
	}
	uploadS3Files(dataFiles, s3Client, testCloudBucketName)
}

func uploadS3Files(dataFiles []string, s3Client *minioClient.Client, bucket string) {
	s3Client.SetAppInfo("Serve-File Test Client", "TEST")
	s3Client.SetCustomTransport(&http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: trustedCACertPool()},
		DisableCompression: true,
	})
	location := testRegion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s3Client.MakeBucket(bucket, location)
	if err != nil {
		exists, err := s3Client.BucketExists(bucket)
		if err == nil && exists {
			log.Printf("We already own %s\n", bucket)
		} else {
			log.Fatalln(err)
		}
	} else {
		log.Printf("Successfully created %s\n", bucket)
	}
	log.Println("Bucket Created...")

	for _, datafile := range dataFiles {
		objectName := datafile
		filePath := fmt.Sprintf("test-data/%s", datafile)
		n, err := s3Client.FPutObjectWithContext(
			ctx, bucket, objectName, filePath, minioClient.PutObjectOptions{ContentType: contentType})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Successfully uploaded %s of size %d.\n", objectName, n)
	}
}

func TestCorrectClientWithS3(t *testing.T) {
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	// TODO: We might do an active check instead
	log.Println("Gonna wait 5s for startup...")
	time.Sleep(5000 * time.Millisecond)

	uploadResolverFiles([]string{
		"401_resolver_cache.bin",
		"402_resolver_cache.bin",
		"403_resolver_cache.bin",
		"403_resolver_cache_v3.bin",
		"404_resolver_cache.bin"})

	uploadCloudResolverFiles([]string{
		"10001_resolver_cache.bin",
	})

	apiURL := "/sinkit/rest/protostream/resolvercache/"
	props := [][]string{
		{"SRV_CA_CERT_PEM_BASE64", caCertBase64},
		{"SRV_SERVER_CERT_PEM_BASE64", serverCertBase64},
		{"SRV_SERVER_KEY_PEM_BASE64", serverKeyBase64},
		{"SRV_BIND_PORT", bindPort},
		{"SRV_BIND_HOST", bindHost},
		{"SRV_API_URL", apiURL},
		{"SRV_API_FILE_DIR", "test-data"},
		{"SRV_OCSP_URL", "http://localhost:" + ocspPort},
		{"SRV_API_USE_S3", "true"},
		{"SRV_S3_ENDPOINT", testEndpoint},
		{"SRV_S3_ACCESS_KEY", testAccessKeyID},
		{"SRV_S3_SECRET_KEY", testSecretAccessKey},
		{"SRV_S3_BUCKET_NAME", testBucketName},
		{"SRV_S3_REGION", testRegion},
		// TODO: run minio with custom certificates (certs/server)
		// test with SRV_S3_USE_OUR_CACERTPOOL=true and SRV_S3_UNSECURE_CONNECTION=false -> GH action will need custom image with certs
		// {"SRV_S3_USE_OUR_CACERTPOOL", "false"}, // if uncommented package level tests fail
		{"SRV_S3_UNSECURE_CONNECTION", "true"},
		{"SRV_CLOUD_S3_CUSTOMER_ID", testCloudCustomerID},
		{"SRV_CLOUD_S3_ENDPOINT", testCloudEndpoint},
		{"SRV_CLOUD_S3_ACCESS_KEY", testCloudAccessKeyID},
		{"SRV_CLOUD_S3_SECRET_KEY", testCloudSecretAccessKey},
		{"SRV_CLOUD_S3_BUCKET_NAME", testCloudBucketName},
		{"SRV_CLOUD_S3_REGION", testCloudRegion},
		{"SRV_AUDIT_LOG_DOWNLOADS", "true"},
	}
	for _, prop := range props {
		os.Setenv(prop[0], prop[1])
	}
	defer func() {
		for _, prop := range props {
			if prop[1] == "true" {
				os.Setenv(prop[0], "false")
			} else {
				os.Setenv(prop[0], "")
			}
		}
	}()
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), true)
	go main()
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	waitForTCP(30*time.Second, fmt.Sprintf("%s:%s", bindHost, bindPort), false)
	ocspCMD := startOCSPResponder(ocspPort, "ocsp", "ca-chain")
	defer stopOCSPResponder(ocspCMD)
	waitForOCSP(10*time.Second, "http://localhost:"+ocspPort, caCertFile, clientCertFile)
	clientNumber := 403
	curl := []string{
		fmt.Sprintf("https://%s:%s%s", bindHost, bindPort, apiURL),
		"--cert",
		fmt.Sprintf("certs/client/certs/client-%d.cert.pem", clientNumber),
		"--key",
		fmt.Sprintf("certs/client/private/client-%d.key.nopass.pem", clientNumber),
		"--cacert",
		"certs/ca/certs/ca-chain.cert.pem",
		"-i",
		"-v",
		//"--trace-ascii", fmt.Sprintf("/tmp/trace-%d", clientNumber),
		//"-k",
	}
	dateCmd := exec.Command("curl", append(curl, []string{fmt.Sprintf("-Hx-resolver-id: %d", clientNumber)}...)...)
	dateOut, err := dateCmd.CombinedOutput()
	assert.Equal(t, err, nil)
	out := string(dateOut)
	expectedContent := fmt.Sprintf("Content-Length: %d", clientNumber)
	assert.True(t, strings.Contains(out, expectedContent), fmt.Sprintf("\"%s\" substring not found in \"%s\".", expectedContent, out))
	assert.True(t, strings.Contains(out, "HTTP/1.1 200"), fmt.Sprintf("\"%s\" substring not found in \"%s\".", "HTTP/1.1 200", out))

	dateCmd = exec.Command("curl", append(curl, []string{"-Hx-version: v3", fmt.Sprintf("-Hx-resolver-id: %d", clientNumber)}...)...)
	dateOut, err = dateCmd.CombinedOutput()
	assert.Equal(t, err, nil)
	out = string(dateOut)
	// Note:  as a matter of test convenience, the _v3 file is 10 times bigger than the default file.
	expectedContent = fmt.Sprintf("Content-Length: %d", clientNumber*10)
	assert.True(t, strings.Contains(out, expectedContent), fmt.Sprintf("\"%s\" substring not found in \"%s\".", expectedContent, out))
	assert.True(t, strings.Contains(out, "HTTP/1.1 200"), fmt.Sprintf("\"%s\" substring not found in \"%s\".", "HTTP/1.1 200", out))

	// get cache as cloud customer 1000042 resolver id 10001
	client := resty.New().
		SetTLSClientConfig(cloudClientCerts()).
		SetHeader("x-resolver-id", testCloudResolverID).
		SetBaseURL(fmt.Sprintf("https://%s:%s%s", bindHost, bindPort, apiURL))

	resp, err := client.R().Get("")

	assert.NoError(t, err)
	assert.Equal(t, "10001 resolver test data", string(resp.Body()))
}

func readFile(path string) []byte {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func trustedCACertPool() *x509.CertPool {
	block, _ := pem.Decode(readFile(caCertFile))
	if block == nil {
		log.Fatal(config.MSG00012)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)

	return caCertPool
}

func cloudClientCerts() *tls.Config {
	cert, err := tls.X509KeyPair(readFile(cloudResolverCert), readFile(cloudResolverKey))
	if err != nil {
		panic(fmt.Sprintf("cloud resolver client certificate invalid %v", err))
	}

	return &tls.Config{
		RootCAs:       trustedCACertPool(),
		Renegotiation: tls.RenegotiateOnceAsClient,
		Certificates:  []tls.Certificate{cert},
	}
}
