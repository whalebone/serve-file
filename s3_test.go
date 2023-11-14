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
	testAccessKeyID     = "minio"
	testSecretAccessKey = "minio123"
	testRegion          = "eu-west-1"
)

var args = []string{
	"minio",
	"--config-dir", "test-data/minio-conf",
	"server",
	"--address", testEndpoint,
	"test-data/minio-data",
}

func cleanMinioTmpFiles() {
	dirsToClean := []string{
		"test-data/minio-data/.minio.sys/tmp",
		"test-data/minio-data/.minio.sys/multipart",
		"test-data/minio-data/.minio.sys/buckets",
		"test-data/minio-data/serve-file",
	}
	for _, dir := range dirsToClean {
		os.RemoveAll(dir)
	}
}

func uploadResolverFiles(dataFiles []string) {
	s3Client, err := minioClient.NewWithRegion(testEndpoint, testAccessKeyID, testSecretAccessKey, false, testRegion)
	if err != nil {
		log.Fatal(err)
	}
	s3Client.SetAppInfo("Serve-File Test Client", "TEST")
	caCertBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(caCertBytes)
	if block == nil {
		log.Fatal(config.MSG00012)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(caCert)
	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{RootCAs: caCertPool},
		DisableCompression: true,
	}
	s3Client.SetCustomTransport(tr)
	location := testRegion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err = s3Client.MakeBucket(testBucketName, location)
	if err != nil {
		exists, err := s3Client.BucketExists(testBucketName)
		if err == nil && exists {
			log.Printf("We already own %s\n", testBucketName)
		} else {
			log.Fatalln(err)
		}
	} else {
		log.Printf("Successfully created %s\n", testBucketName)
	}
	log.Println("Bucket Created...")

	for _, datafile := range dataFiles {
		objectName := datafile
		filePath := fmt.Sprintf("test-data/%s", datafile)
		n, err := s3Client.FPutObjectWithContext(
			ctx, testBucketName, objectName, filePath, minioClient.PutObjectOptions{ContentType: contentType})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Successfully uploaded %s of size %d.\n", objectName, n)
	}
}

func TestCorrectClientWithS3(t *testing.T) {
	defer syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	defer cleanMinioTmpFiles()
	// TODO: We might do an active check instead
	log.Println("Gonna wait 5s for startup...")
	time.Sleep(5000 * time.Millisecond)

	uploadResolverFiles([]string{
		"401_resolver_cache.bin",
		"402_resolver_cache.bin",
		"403_resolver_cache.bin",
		"403_resolver_cache_v3.bin",
		"404_resolver_cache.bin"})

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
		{"SRV_S3_USE_OUR_CACERTPOOL", "true"},
		{"SRV_S3_UNSECURE_CONNECTION", "true"},
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
}
