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

const (
	MSG00001 string = "SRV_CA_CERT_PEM_BASE64 is not a valid base64."
	MSG00002 string = "SRV_CA_CERT_PEM_FILE is not a valid file."
	MSG00003 string = "Neither SRV_CA_CERT_PEM_BASE64 nor SRV_CA_CERT_PEM_FILE are set."
	MSG00004 string = "SRV_CA_CERT_PEM_ does not contain a valid certificate."
	MSG00005 string = "SRV_SERVER_CERT_PEM_BASE64 is not a valid base64."
	MSG00006 string = "SRV_SERVER_CERT_PEM_FILE is not a valid file."
	MSG00007 string = "Neither SRV_SERVER_CERT_PEM_BASE64 nor SRV_SERVER_CERT_PEM_FILE are set."
	MSG00008 string = "SRV_SERVER_KEY_PEM_BASE64 is not a valid base64."
	MSG00009 string = "SRV_SERVER_KEY_PEM_FILE is not a valid file."
	MSG00010 string = "Neither SRV_SERVER_KEY_PEM_BASE64 nor SRV_SERVER_KEY_PEM_FILE are set."
	MSG00011 string = "SRV_SERVER_KEY_PEM_, SRV_SERVER_CERT_PEM_ does not contain a valid server cert key pair."
	MSG00012 string = "SRV_CA_CERT_PEM provided is invalid or a malformed PEM and cannot be decoded."
	MSG00013 string = "SRV_NUM_OF_CPUS not set, defaulting to %d."
	MSG00014 string = "SRV_BIND_HOST not set, defaulting to %s."
	MSG00015 string = "%d long SRV_BIND_HOST is too long. Could the property be mixed up with a BASE64 cert one?"
	MSG00016 string = "%d is not a valid port number, check SRV_BIND_PORT property."
	MSG00017 string = "No SRV_READ_TIMEOUT_S set, defaulting to %ds."
	MSG00018 string = "No SRV_READ_HEADER_TIMEOUT_S set, defaulting to %ds."
	MSG00019 string = "No SRV_WRITE_TIMEOUT_S set, defaulting to %ds."
	MSG00020 string = "No SRV_IDLE_TIMEOUT_S set, defaulting to %ds."
	MSG00021 string = "No SRV_MAX_HEADER_BYTES set, defaulting to %d."
	MSG00022 string = "SRV_CRL_PEM_BASE64 is not a valid base64."
	MSG00023 string = "SRV_CRL_PEM_FILE is not a valid file."
	MSG00024 string = "Neither SRV_CRL_PEM_BASE64 nor SRV_CRL_PEM_FILE are set. CRL mechanism will not be used."
	MSG00025 string = "Check SRV_CRL_PEM_  property. It contains invalid CRL PEM data."
	MSG00026 string = "It seems SRV_OCSP_URL is set, but it doesn't start with \"http\". Is it correct?"
	MSG00027 string = "SRV_OCSP_URL is not set, OCSP will not be used."
	MSG00028 string = "SRV_API_URL was not set, defaulting to %s."
	MSG00029 string = "SRV_API_MIME_TYPE was not set, defaulting to %s."
	MSG00030 string = "SRV_API_ID_REQ_HEADER was not set, defaulting to %s."
	MSG00031 string = "SRV_API_FILE_DIR was not set, defaulting to %s."
	MSG00032 string = "SRV_API_DATA_FILE_TEMPLATE was not set, defaulting to %s."
	MSG00033 string = "SRV_API_HASH_FILE_TEMPLATE was not set, defaulting to %s."
	MSG00034 string = "SRV_API_RSP_TRY_LATER_HTTP_CODE was not set, defaulting to %d."
	MSG00035 string = "SRV_API_RSP_ERROR_HEADER was not set, defaulting to %s."
	MSG00036 string = "SRV_API_RSP_FILE_LENGTH_HEADER was not set, defaulting to %s."
	MSG00037 string = "SRV_API_RSP_FILE_HASH_HEADER was not set, defaulting to %s."
	MSG00038 string = "SRV_FILE_CACHE_PURGING_PERIOD_S was not set, defaulting to %ds."
	MSG00039 string = "SRV_FILE_CACHE_EXPIRY_S was not set, defaulting to %ds."
	MSG00040 string = "SRV_API_USE_S3 set to True, system will use S3 instead of local filesystem."
	MSG00041 string = "SRV_API_USE_S3 set to False, system will use local filesystem instead of S3."
	MSG00042 string = "SRV_S3_ENDPOINT must be set while SRV_API_USE_S3 is True."
	MSG00043 string = "SRV_S3_ACCESS_KEY must be set while SRV_API_USE_S3 is True."
	MSG00044 string = "SRV_S3_SECRET_KEY must be set while SRV_API_USE_S3 is True."
	MSG00045 string = "SRV_S3_BUCKET_NAME must be set while SRV_API_USE_S3 is True."
	MSG00046 string = "SRV_S3_REGION must be set while SRV_API_USE_S3 is True."
	MSG00047 string = "SRV_S3_DATA_FILE_TEMPLATE was not set, defaulting to %s."
	MSG00048 string = "SRV_S3_GET_OBJECT_TIMEOUT_S was not set, defaulting to %ds."

	MSG00049 string = "SRV_CLOUD_S3_ENDPOINT must be set while SRV_API_USE_S3 is True."
	MSG00050 string = "SRV_CLOUD_S3_ACCESS_KEY must be set while SRV_API_USE_S3 is True."
	MSG00051 string = "SRV_CLOUD_S3_SECRET_KEY must be set while SRV_API_USE_S3 is True."
	MSG00052 string = "SRV_CLOUD_S3_BUCKET_NAME must be set while SRV_API_USE_S3 is True."
	MSG00053 string = "SRV_CLOUD_S3_REGION must be set while SRV_API_USE_S3 is True."
	MSG00054 string = "SRV_CLOUD_S3_DATA_FILE_TEMPLATE was not set, defaulting to %s."
	MSG00055 string = "SRV_CLOUD_S3_DATA_FILE_TEMPLATE was not set, defaulting to %s."
	MSG00056 string = "CLOUD_S3_CUSTOMER_ID set, system will use cloud S3 for this customer ID"

	RSP00001 string = "Your certificate cannot be validated. Go away."
	RSL00001 string = "TLS not used. It should have been rejected earlier. Server misconfig?"
	RSP00002 string = "Your certificate is revoked in CRL. Go away."
	RSL00002 string = "Client cert CommonName %s is revoked in CRL. Client sent away."
	RSP00003 string = "Your certificate cannot be validated with OCSP. Try again later."
	RSL00003 string = "Client cert CommonName %s could not be validated with OCSP. Client sent away. Is OCSP %s up and running?"
	RSP00004 string = "Your certificate is revoked in OCSP. Go away."
	RSL00004 string = "Client cert CommonName %s is revoked by OCSP %s. Client sent away."
	RSP00005 string = "%s request header is not set to a number."
	RSL00005 string = "Client with cert CommonName %s is misconfigured. It does not set %s request header to a valid uint64."
	RSP00006 string = "Your certificate CommonName is not a number. Go away."
	RSL00006 string = "Client cert CommonName is not uint64. Client sent away."
	RSP00007 string = "Your id from CommonName %d does not match id %d from %s header. Go away."
	RSL00007 string = "Client CommonName %d does not match id %d parsed from %s header. Client sent away."
	RSP00008 string = "There is no data file ready for you. Try again later."
	RSL00008 string = "There is no file on path %s ready for client CommonName %d. Subject: %s. Client sent away."
	RSP00009 string = "Cannot provide datafile hash for you. Try again later."
	RSL00009 string = "There is no hash on path %s ready for client CommonName %d. Although data file on path %s exists. Client sent away."
	RSP00010 string = "There is no data file ready for you. Try again later."
	RSL00010 string = "There is no S3 object %s ready for client CommonName %d. Subject: %s. Client sent away."
	RSP00011 string = "There is something wrong on the server side. Contact administrator."
	RSL00011 string = "S3 error getting object %s for client CommonName %d. Code: `%s', Message: `%s'. Check bucket name. Client sent away."
	RSL00012 string = "S3 error in client connection to get object %s, Error: `%s'. Client sent away."
	RSL00013 string = "S3 connection failed very early. Check backend, check TLS to endpoint, check SRV_S3_USE_OUR_CACERTPOOL when testing."
	RSP00014 string = "Fatal configuration error on the server side. Contact admin."
	RSL00014 string = "Client sent away. Fatal MINIO S3 configuration Error: %s"
	RSL00015 string = "Begin session %d: Client: CommonName %d, Organization: %s, download file: %s."
	RSL00016 string = "End session %d: Client: CommonName %d, Organization: %s, download file: %s."
)
