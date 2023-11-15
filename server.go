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
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	minio "github.com/minio/minio-go"
	"whalebone.io/serve-file/app"
	"whalebone.io/serve-file/config"
	"whalebone.io/serve-file/validation"
)

//nolint:gocognit,cyclop
func createServer(settings *config.Settings) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(settings.API_URL, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if r.TLS == nil {
			log.Printf(config.RSL00001)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00001)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		idFromCertStr := string(r.TLS.VerifiedChains[0][0].Subject.CommonName)
		var idFromCert int64
		idFromCert, err := strconv.ParseInt(idFromCertStr, 10, 64)
		if err != nil {
			log.Printf(config.RSL00006)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00006)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if settings.CRL != nil && validation.CertIsRevokedCRL(r.TLS.VerifiedChains[0][0], settings.CRL) {
			log.Printf(config.RSL00002, idFromCertStr)
			w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00002)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if len(settings.OCSP_URL) > 0 {
			if revoked, ok := validation.CertIsRevokedOCSP(r.TLS.VerifiedChains[0][0], settings.CACert, settings.OCSP_URL); !ok {
				log.Printf(config.RSL00003, idFromCertStr, settings.OCSP_URL)
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00003)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			} else if revoked {
				log.Printf(config.RSL00004, idFromCertStr, settings.OCSP_URL)
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00004)
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		var idFromHeader int64
		idFromHeader, err = strconv.ParseInt(
			strings.Trim(r.Header.Get(settings.API_ID_REQ_HEADER), " "), 10, 64)
		if err != nil {
			log.Printf(config.RSL00005, idFromCertStr, settings.API_ID_REQ_HEADER)
			w.Header().Set(settings.API_RSP_ERROR_HEADER,
				fmt.Sprintf(config.RSP00005, settings.API_ID_REQ_HEADER))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if idFromCert != idFromHeader {
			log.Printf(config.RSL00007, idFromCert, idFromHeader, settings.API_ID_REQ_HEADER)
			w.Header().Set(settings.API_RSP_ERROR_HEADER,
				fmt.Sprintf(config.RSP00007, idFromCert, idFromHeader, settings.API_ID_REQ_HEADER))
			w.WriteHeader(http.StatusForbidden)
			return
		}

		version := strings.Trim(r.Header.Get(settings.API_VERSION_REQ_HEADER), " ")
		if len(version) > 0 {
			version = fmt.Sprintf("_%s", version)
		}

		if settings.API_USE_S3 {
			objectName := fmt.Sprintf(settings.S3_DATA_FILE_TEMPLATE, idFromCertStr, version)
			// TODO: Move client initialization elsewhere. It is wasteful to do it each time.
			s3Client, clientErr := minio.New(settings.S3_ENDPOINT, settings.S3_ACCESS_KEY, settings.S3_SECRET_KEY, !settings.S3_UNSECURE_CONNECTION)
			if clientErr != nil {
				log.Printf(config.RSL00014, clientErr.Error())
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00014)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if settings.S3_USE_OUR_CACERTPOOL {
				tr := &http.Transport{
					TLSClientConfig:    &tls.Config{RootCAs: settings.CACertPool, MinVersion: tls.VersionTLS12},
					DisableCompression: true,
				}
				s3Client.SetCustomTransport(tr)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(settings.S3_GET_OBJECT_TIMEOUT_S)*time.Second)
			defer cancel()
			opts := minio.GetObjectOptions{}
			// https://tools.ietf.org/html/rfc7232#section-3.2
			etag := r.Header.Get("If-None-Match")
			if etag != "" {
				//opts.SetMatchETagExcept(etag) <-- this is buggy, it sets ""etag"" and get 403 from proper S3 server. Passes with MINIO backend though.
				opts.Set("If-None-Match", etag)
			}
			//s3Client.TraceOn(nil)
			object, err := s3Client.GetObjectWithContext(ctx, settings.S3_BUCKET_NAME, objectName, opts)
			if err != nil {
				log.Printf(config.RSL00012, objectName, err.Error())
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00011)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer object.Close()
			objectInfo, err := object.Stat()
			if err != nil {
				errResp := minio.ToErrorResponse(err)
				if errResp.StatusCode == 404 {
					log.Printf(config.RSL00010, objectName, idFromCert, r.TLS.VerifiedChains[0][0].Subject.String())
					w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00010)
					w.WriteHeader(settings.API_RSP_TRY_LATER_HTTP_CODE)
					return
				} else if errResp.StatusCode == 304 {
					w.WriteHeader(http.StatusNotModified)
					return
				} else if errResp.StatusCode == 0 {
					log.Printf(config.RSL00013)
					log.Printf("%v", err)
					w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00011)
					w.WriteHeader(http.StatusInternalServerError)
					return
				} else {
					log.Printf(config.RSL00011, objectName, idFromCert, errResp.Code, errResp.Message)
					log.Printf("%v", err)
					w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00011)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
			// https://tools.ietf.org/html/rfc7232#section-2.3
			w.Header().Set("ETag", objectInfo.ETag)
			// time.Time{} -- disables Modified since. We use ETag instead.
			var timestamp int64
			if settings.AUDIT_LOG_DOWNLOADS {
				timestamp = time.Now().UnixNano()
				log.Printf(config.RSL00015, timestamp, idFromCert, r.TLS.VerifiedChains[0][0].Subject.Organization[0], objectName)
			}
			http.ServeContent(w, r, objectName, time.Time{}, object)
			if settings.AUDIT_LOG_DOWNLOADS {
				log.Printf(config.RSL00016, timestamp, idFromCert, r.TLS.VerifiedChains[0][0].Subject.Organization[0], objectName)
			}
		} else {
			pathToDataFile := fmt.Sprintf(
				settings.API_DATA_FILE_TEMPLATE,
				settings.API_FILE_DIR,
				idFromCertStr,
				version,
			)
			// We do not read the file in memory, just metadata to check it exists.
			_, err = os.Stat(pathToDataFile)
			if err != nil {
				log.Printf(config.RSL00008, pathToDataFile, idFromCert, r.TLS.VerifiedChains[0][0].Subject.String())
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00008)
				w.WriteHeader(settings.API_RSP_TRY_LATER_HTTP_CODE)
				return
			}
			pathToHashFile := fmt.Sprintf(
				settings.API_HASH_FILE_TEMPLATE,
				settings.API_FILE_DIR,
				idFromCertStr,
			)
			// We do read the hash file at once, just 32 bytes...
			hash, err := os.ReadFile(pathToHashFile)
			if err != nil {
				log.Printf(config.RSL00009, pathToHashFile, idFromCert, pathToDataFile)
				w.Header().Set(settings.API_RSP_ERROR_HEADER, config.RSP00009)
				w.WriteHeader(settings.API_RSP_TRY_LATER_HTTP_CODE)
				return
			}
			etag := "\"" + string(hash) + "\"" // Well, we know the size of byte[], do we really need all those extra allocs?
			// https://tools.ietf.org/html/rfc7232#section-2.3
			w.Header().Set("ETag", etag)
			// https://tools.ietf.org/html/rfc7232#section-3.2
			if etag == r.Header.Get("If-None-Match") {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			var timestamp int64
			if settings.AUDIT_LOG_DOWNLOADS {
				timestamp = time.Now().UnixNano()
				log.Printf(config.RSL00015, timestamp, idFromCert, r.TLS.VerifiedChains[0][0].Subject.Organization[0], pathToDataFile)
			}
			http.ServeFile(w, r, pathToDataFile)
			if settings.AUDIT_LOG_DOWNLOADS {
				log.Printf(config.RSL00016, timestamp, idFromCert, r.TLS.VerifiedChains[0][0].Subject.Organization[0], pathToDataFile)
			}
		}
		return
	})
	tlsCfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    settings.CACertPool,
		Certificates: []tls.Certificate{settings.ServerKeyPair},
	}
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", settings.BIND_HOST, settings.BIND_PORT),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadTimeout:       time.Duration(settings.READ_TIMEOUT_S) * time.Second,
		ReadHeaderTimeout: time.Duration(settings.READ_HEADER_TIMEOUT_S) * time.Second,
		WriteTimeout:      time.Duration(settings.WRITE_TIMEOUT_S) * time.Second,
		IdleTimeout:       time.Duration(settings.IDLE_TIMEOUT_S) * time.Second,
		MaxHeaderBytes:    settings.MAX_HEADER_BYTES,
	}
	return srv
}

func main() {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	settings := config.LoadSettings()

	if settings.ENABLE_PROFILE {
		go func() {
			log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
		}()
	}

	srv := createServer(&settings)
	l, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatal(err)
	}
	tlsListener := tls.NewListener(l, srv.TLSConfig)
	go func(s *http.Server) {
		if err := srv.Serve(tlsListener); err != nil {
			log.Println(err)
		}
	}(srv)
	go func(s *http.Server) {
		sig := <-sigs
		log.Println(sig)
		if srv != nil {
			if err := srv.Close(); err != nil {
				log.Fatalf("Close error: %s", err.Error())
			}
			if err := srv.Shutdown(nil); err != nil {
				log.Fatalf("Shutdown error: %s", err.Error())
			}
		}
		done <- true
	}(srv)
	log.Printf("Running version %s (%s). Ctrl+C to stop.", app.Version, app.GitCommit)
	<-done
	log.Printf("Stopped.")
}
