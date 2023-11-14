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
package validation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

var ocspOpts = ocsp.RequestOptions{
	Hash: crypto.SHA1,
}
var ocspRead = io.ReadAll

func CertIsRevokedCRL(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, revoked := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func CertIsRevokedOCSP(leaf *x509.Certificate, caCert *x509.Certificate, ocspURL string) (revoked, ok bool) {
	ocspRequest, err := ocsp.CreateRequest(leaf, caCert, &ocspOpts)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	resp, err := SendOCSPRequest(ocspURL, ocspRequest, leaf, caCert)
	if err != nil {
		log.Printf(err.Error())
		return
	}
	ok = true
	if resp.Status != ocsp.Good {
		revoked = true
	}
	return
}

// TODO: Data race?
func SendOCSPRequest(server string, req []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	var resp *http.Response
	var err error
	buf := bytes.NewBuffer(req)
	resp, err = http.Post(server, "application/ocsp-request", buf)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve OSCP resonse")
	}
	body, err := ocspRead(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case bytes.Equal(body, ocsp.SigRequredErrorResponse):
		return nil, errors.New("Signature required")
	case bytes.Equal(body, ocsp.UnauthorizedErrorResponse):
		return nil, errors.New("Unauthorized")
	case bytes.Equal(body, ocsp.TryLaterErrorResponse):
		return nil, errors.New("Try again later")
	case bytes.Equal(body, ocsp.MalformedRequestErrorResponse):
		return nil, errors.New("Malformed request")
	case bytes.Equal(body, ocsp.InternalErrorErrorResponse):
		return nil, errors.New("Internal error occured")
	}

	return ocsp.ParseResponseForCert(body, leaf, issuer)
}
