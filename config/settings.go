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
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

//nolint:revive,stylecheck
type Settings struct {
	// Network
	BIND_HOST string
	BIND_PORT uint16

	// Certificates - if both _BASE64 and _FILE are set, _BASE64 takes precedence.
	CA_CERT_PEM_BASE64     string
	CA_CERT_PEM_FILE       string
	SERVER_CERT_PEM_BASE64 string
	SERVER_CERT_PEM_FILE   string
	SERVER_KEY_PEM_BASE64  string
	SERVER_KEY_PEM_FILE    string

	// CRL / OCSP mechanism
	// If no revocation mechanism is set, this validation step is omitted.
	// If more than one mechanism is set, all are checked in sequence in the undermentioned order.
	// If a mechanism is set and it fails (CRL expires and renewal fails, OCSP does not reply)
	// it is a hard failure, the client is rejected and the connection is closed.
	//
	// The current version *ignores* CRL/OCSP information baked into client certificates.
	//
	CRL_PEM_BASE64 string
	CRL_PEM_FILE   string
	OCSP_URL       string

	// Web server
	READ_TIMEOUT_S        uint16
	READ_HEADER_TIMEOUT_S uint16
	WRITE_TIMEOUT_S       uint16
	IDLE_TIMEOUT_S        uint16
	MAX_HEADER_BYTES      int

	NUM_OF_CPUS         int
	ENABLE_PROFILE      bool
	AUDIT_LOG_DOWNLOADS bool

	API_URL                     string
	API_ID_REQ_HEADER           string
	API_VERSION_REQ_HEADER      string
	API_RSP_TRY_LATER_HTTP_CODE int
	API_RSP_ERROR_HEADER        string

	API_FILE_DIR           string
	API_DATA_FILE_TEMPLATE string
	API_HASH_FILE_TEMPLATE string

	API_USE_S3              bool
	S3_ENDPOINT             string
	S3_ACCESS_KEY           string
	S3_SECRET_KEY           string
	S3_BUCKET_NAME          string
	S3_DATA_FILE_TEMPLATE   string
	S3_REGION               string
	S3_GET_OBJECT_TIMEOUT_S uint16
	S3_USE_OUR_CACERTPOOL   bool
	S3_UNSECURE_CONNECTION  bool

	ServerKeyPair tls.Certificate
	CACertPool    *x509.CertPool
	CACert        *x509.Certificate
	CRL           *x509.RevocationList
}

func LoadSettings() Settings {
	// Load settings
	var settings Settings
	err := envconfig.Process("SRV", &settings)
	if err != nil {
		log.Fatal(err.Error())
	}
	settings.CACertPool = x509.NewCertPool()

	// Cap on goroutines going haywire
	if settings.NUM_OF_CPUS <= 0 || settings.NUM_OF_CPUS > runtime.NumCPU() {
		settings.NUM_OF_CPUS = runtime.NumCPU()
		log.Printf(MSG00013, settings.NUM_OF_CPUS)
	}

	// Host, port
	if len(settings.BIND_HOST) == 0 {
		settings.BIND_HOST = "localhost"
		log.Printf(MSG00014, settings.BIND_HOST)
	}
	if len(settings.BIND_HOST) > 255 {
		log.Fatal(fmt.Sprintf(MSG00015, len(settings.BIND_HOST)))
	}
	if settings.BIND_PORT == 0 {
		log.Fatal(fmt.Sprintf(MSG00016, settings.BIND_PORT))
	}

	// Web server params
	if settings.READ_TIMEOUT_S == 0 {
		settings.READ_TIMEOUT_S = 10
		log.Printf(MSG00017, settings.READ_TIMEOUT_S)
	}
	if settings.READ_HEADER_TIMEOUT_S == 0 {
		settings.READ_HEADER_TIMEOUT_S = 10
		log.Printf(MSG00018, settings.READ_HEADER_TIMEOUT_S)
	}
	if settings.WRITE_TIMEOUT_S == 0 {
		settings.WRITE_TIMEOUT_S = 300
		log.Printf(MSG00019, settings.WRITE_TIMEOUT_S)
	}
	if settings.IDLE_TIMEOUT_S == 0 {
		settings.IDLE_TIMEOUT_S = 60
		log.Printf(MSG00020, settings.IDLE_TIMEOUT_S)
	}
	if settings.MAX_HEADER_BYTES == 0 {
		settings.MAX_HEADER_BYTES = 102400
		log.Printf(MSG00021, settings.MAX_HEADER_BYTES)
	}

	// CRL
	var crlBytes []byte
	if len(settings.CRL_PEM_BASE64) > 0 {
		crlBytes, err = base64.StdEncoding.DecodeString(settings.CRL_PEM_BASE64)
		if err != nil {
			log.Fatal(MSG00022, err)
		}
	}
	if len(settings.CRL_PEM_FILE) > 0 {
		crlBytes, err = os.ReadFile(settings.CRL_PEM_FILE)
		if err != nil {
			log.Fatal(MSG00023, err)
		}
	}
	if len(crlBytes) > 1 {
		settings.CRL, err = x509.ParseRevocationList(crlBytes)
		if err != nil {
			log.Fatal(MSG00025, err)
		}
	} else {
		log.Println(MSG00024)
	}

	// OCSP
	if len(settings.OCSP_URL) > 0 {
		if !strings.HasPrefix(settings.OCSP_URL, "http") {
			log.Fatal(MSG00026)
		}
	} else {
		log.Println(MSG00027)
	}

	// CA cert
	var caCertBytes []byte
	if len(settings.CA_CERT_PEM_BASE64) > 0 {
		caCertBytes, err = base64.StdEncoding.DecodeString(settings.CA_CERT_PEM_BASE64)
		if err != nil {
			log.Fatal(MSG00001, err)
		}
	} else if len(settings.CA_CERT_PEM_FILE) > 0 {
		caCertBytes, err = os.ReadFile(settings.CA_CERT_PEM_FILE)
		if err != nil {
			log.Fatal(MSG00002, err)
		}
	} else {
		log.Fatal(MSG00003)
	}
	block, _ := pem.Decode(caCertBytes)
	if block == nil {
		log.Fatal(MSG00012)
	}
	settings.CACert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(MSG00004, err)
	}
	settings.CACertPool.AddCert(settings.CACert)

	// Server cert key pair
	var serverCert []byte
	if len(settings.SERVER_CERT_PEM_BASE64) > 0 {
		serverCert, err = base64.StdEncoding.DecodeString(settings.SERVER_CERT_PEM_BASE64)
		if err != nil {
			log.Fatal(MSG00005, err)
		}
	} else if len(settings.SERVER_CERT_PEM_FILE) > 0 {
		serverCert, err = os.ReadFile(settings.SERVER_CERT_PEM_FILE)
		if err != nil {
			log.Fatal(MSG00006, err)
		}
	} else {
		log.Fatal(MSG00007)
	}
	var serverKey []byte
	if len(settings.SERVER_KEY_PEM_BASE64) > 0 {
		serverKey, err = base64.StdEncoding.DecodeString(settings.SERVER_KEY_PEM_BASE64)
		if err != nil {
			log.Fatal(MSG00008, err)
		}
	} else if len(settings.SERVER_KEY_PEM_FILE) > 0 {
		serverKey, err = os.ReadFile(settings.SERVER_KEY_PEM_FILE)
		if err != nil {
			log.Fatal(MSG00009, err)
		}
	} else {
		log.Fatal(MSG00010)
	}
	settings.ServerKeyPair, err = tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		log.Fatal(MSG00011, err)
	}

	// API settings
	if len(settings.API_URL) == 0 {
		settings.API_URL = "/sinkit/rest/protostream/resolvercache/"
		log.Printf(MSG00028, settings.API_URL)
	}
	if len(settings.API_ID_REQ_HEADER) == 0 {
		settings.API_ID_REQ_HEADER = "x-resolver-id"
		log.Printf(MSG00030, settings.API_ID_REQ_HEADER)
	}
	if len(settings.API_VERSION_REQ_HEADER) == 0 {
		settings.API_VERSION_REQ_HEADER = "x-version"
		log.Printf(MSG00030, settings.API_VERSION_REQ_HEADER)
	}
	if settings.API_RSP_TRY_LATER_HTTP_CODE <= 0 {
		settings.API_RSP_TRY_LATER_HTTP_CODE = 466
		log.Printf(MSG00034, settings.API_RSP_TRY_LATER_HTTP_CODE)
	}
	if len(settings.API_RSP_ERROR_HEADER) == 0 {
		settings.API_RSP_ERROR_HEADER = "X-error"
		log.Printf(MSG00035, settings.API_RSP_ERROR_HEADER)
	}
	// S3 storage
	if settings.API_USE_S3 {
		log.Println(MSG00040)
		if len(settings.S3_ENDPOINT) == 0 {
			log.Fatal(MSG00042)
		}
		if len(settings.S3_ACCESS_KEY) == 0 {
			log.Fatal(MSG00043)
		}
		if len(settings.S3_SECRET_KEY) == 0 {
			log.Fatal(MSG00044)
		}
		if len(settings.S3_BUCKET_NAME) == 0 {
			log.Fatal(MSG00045)
		}
		if len(settings.S3_REGION) == 0 {
			log.Fatal(MSG00046)
		}
		if len(settings.S3_DATA_FILE_TEMPLATE) == 0 {
			settings.S3_DATA_FILE_TEMPLATE = "%s_resolver_cache%s.bin"
			log.Printf(MSG00047, settings.S3_DATA_FILE_TEMPLATE)
		}
		if settings.S3_GET_OBJECT_TIMEOUT_S == 0 {
			settings.S3_GET_OBJECT_TIMEOUT_S = 180
			log.Printf(MSG00048, settings.S3_GET_OBJECT_TIMEOUT_S)
		}
	} else {
		// Local filesystem
		log.Println(MSG00041)
		if len(settings.API_FILE_DIR) == 0 {
			settings.API_FILE_DIR = "/opt/sinkit/protobuf"
			log.Printf(MSG00031, settings.API_FILE_DIR)
		}
		if len(settings.API_DATA_FILE_TEMPLATE) == 0 {
			settings.API_DATA_FILE_TEMPLATE = "%s/%s_resolver_cache%s.bin"
			log.Printf(MSG00032, settings.API_DATA_FILE_TEMPLATE)
		}
		if len(settings.API_HASH_FILE_TEMPLATE) == 0 {
			settings.API_HASH_FILE_TEMPLATE = "%s/%s_resolver_cache.bin.md5"
			log.Printf(MSG00033, settings.API_HASH_FILE_TEMPLATE)
		}
	}
	return settings
}
