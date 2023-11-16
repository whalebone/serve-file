#!/usr/bin/env bash
# Blame: Michal Karm Babacek
set -e
set -x

CA_DIR=trustchain/ca
INTERM_DIR="${CA_DIR}/intermediate"
CONF_DIR="$(pwd)/certs/conf"
INTERM_CNF_FILE="${CONF_DIR}/openssl_intermediate.conf"
CA_CONFIG_FILE="${CONF_DIR}/openssl_ca.conf"
PASSPHRASE=ChangeIt
EXPIRATION_DAYS=3650
SUBJECT_LINE=""

function initialize_cert_dir() {
    echo 1000 >serial
    echo 1000 >crlnumber
    touch index.txt
}

function prime_dirs() {
    mkdir -p ${CA_DIR}
    pushd ${CA_DIR}
    mkdir private certs intermediate newcerts
    initialize_cert_dir
    popd
    pushd ${INTERM_DIR}
    mkdir certs crl csr newcerts private
    initialize_cert_dir
    popd
}

function generate_intermediate_signed_cert_using_extension() {
    NAME="$1"
    EXTENSION="$2"
    COMMON_NAME="$3"
    LOCATION="${4-999}" # defaults to 999
    if [[ "${EXTENSION}" == "server_cert" ]]; then
        SUBJECT_LINE="/C=CZ/ST=Czech Republic/L=Brno/O=Michal Karm Babacek/OU=Testing/emailAddress=karm@email.cz/CN=${COMMON_NAME}"
    else
        SUBJECT_LINE="/C=CZ/ST=Czech Republic/L=${LOCATION}/O=Michal Karm Babacek ID: ${LOCATION}/OU=Testing/emailAddress=karm@email.cz/CN=${COMMON_NAME}"
    fi
    openssl genrsa -aes256 \
        -passout pass:${PASSPHRASE} \
        -out ${INTERM_DIR}/private/${NAME}.key.pem 4096
    openssl rsa -in ${INTERM_DIR}/private/${NAME}.key.pem -passin pass:${PASSPHRASE} \
        -out ${INTERM_DIR}/private/${NAME}.key.nopass.pem
    openssl req -config "${INTERM_CNF_FILE}" \
        -passin pass:${PASSPHRASE} \
        -subj "${SUBJECT_LINE}" \
        -key ${INTERM_DIR}/private/${NAME}.key.pem \
        -new -sha512 -out ${INTERM_DIR}/csr/${NAME}.csr.pem
    openssl ca -config "${INTERM_CNF_FILE}" \
        -batch \
        -subj "${SUBJECT_LINE}" \
        -extensions ${EXTENSION} -days ${EXPIRATION_DAYS} -notext -md sha512 \
        -passin pass:${PASSPHRASE} \
        -in ${INTERM_DIR}/csr/${NAME}.csr.pem \
        -out ${INTERM_DIR}/certs/${NAME}.cert.pem
}

function srv_gen_crt() {
    NAME="$1"
    COMMON_NAME="$2"
    if [[ "${NAME}" == "ocsp" ]]; then
        generate_intermediate_signed_cert_using_extension ${NAME} "server_cert_ocsp" ${COMMON_NAME}
    else
        generate_intermediate_signed_cert_using_extension ${NAME} "server_cert" ${COMMON_NAME}
    fi
}

function usr_gen_crt() {
    NAME="$1"
    COMMON_NAME="$2"
    OCSP="$3"
    LOCATION="$4"
    if [[ "${OCSP}" == "ocsp" ]]; then
        generate_intermediate_signed_cert_using_extension ${NAME} "usr_cert_ocsp" ${COMMON_NAME} ${LOCATION}
    else
        generate_intermediate_signed_cert_using_extension ${NAME} "usr_cert" ${COMMON_NAME} ${LOCATION}
    fi
}

function create_certificate_revocation_list() {
    openssl ca -config "$INTERM_CNF_FILE" \
        -passin pass:${PASSPHRASE} \
        -gencrl -out ${INTERM_DIR}/crl/intermediate.crl.pem \
        -crldays ${EXPIRATION_DAYS}
}

function revoke_certificate() {
    NAME="$1"
    openssl ca -revoke "${INTERM_DIR}/certs/${NAME}.cert.pem" \
        -passin pass:${PASSPHRASE} \
        -keyfile "${CA_DIR}/private/ca.key.pem" \
        -cert "${CA_DIR}/certs/ca.cert.pem" \
        -config "$INTERM_CNF_FILE" \
        -crl_reason cessationOfOperation
}

function trust_chain_gen() {
    CA_FILE_NAME="$1"
    INTERM_FILE_NAME="$2"
    SUBJECT_LINE="/C=CZ/ST=Czech Republic/L=Brno/O=Michal Karm Babacek/OU=Testing/emailAddress=karm@email.cz/CN=Testing CA"
    pushd ${CA_DIR}
    openssl genrsa -aes256 -out private/${CA_FILE_NAME}.key.pem -passout pass:${PASSPHRASE} 4096
    openssl genrsa -aes256 \
        -out intermediate/private/${INTERM_FILE_NAME}.key.pem \
        -passout pass:${PASSPHRASE} 4096
    SUBJECT_LINE="/C=CZ/ST=Czech Republic/L=Brno/O=Michal Karm Babacek/OU=Testing/emailAddress=karm@email.cz/CN=Root Testing CA"
    openssl req -config "$CA_CONFIG_FILE" \
        -subj "${SUBJECT_LINE}" \
        -passin pass:${PASSPHRASE} \
        -key private/${CA_FILE_NAME}.key.pem \
        -new -x509 -days ${EXPIRATION_DAYS} -sha512 -extensions v3_ca \
        -out certs/${CA_FILE_NAME}.cert.pem
    popd
    SUBJECT_LINE="/C=CZ/ST=Czech Republic/L=Brno/O=Michal Karm Babacek/OU=Testing/emailAddress=karm@email.cz/CN=Intermediate certificate"
    openssl req -config "${INTERM_CNF_FILE}" -new -sha512 \
        -subj "${SUBJECT_LINE}" \
        -passin pass:${PASSPHRASE} \
        -key ${INTERM_DIR}/private/${INTERM_FILE_NAME}.key.pem \
        -out ${INTERM_DIR}/csr/${INTERM_FILE_NAME}.csr.pem
    openssl ca -config "$CA_CONFIG_FILE" -extensions v3_intermediate_ca \
        -subj "${SUBJECT_LINE}" \
        -batch \
        -passin pass:${PASSPHRASE} \
        -days ${EXPIRATION_DAYS} -notext -md sha512 \
        -in ${INTERM_DIR}/csr/${INTERM_FILE_NAME}.csr.pem \
        -out ${INTERM_DIR}/certs/${INTERM_FILE_NAME}.cert.pem
    cat ${INTERM_DIR}/certs/${INTERM_FILE_NAME}.cert.pem \
        ${CA_DIR}/certs/${CA_FILE_NAME}.cert.pem >${INTERM_DIR}/certs/${CA_FILE_NAME}-chain.cert.pem
}

function archive_certs() {
    PREFIX="${1}"
    typeset -A certsmask
    certsmask=(
        ["*ca*cert.pem*"]=ca/certs/
        ["*ca*key.pem*"]=ca/private/
        ["*client*cert.pem*"]=client/certs/
        ["*client*nopass.pem*"]=client/private/
        ["*server*cert.pem*"]=server/certs/
        ["*server*nopass.pem*"]=server/private/
        ["*ocsp*cert.pem*"]=ocsp/certs/
        ["*ocsp*nopass.pem*"]=ocsp/private/
        ["*crl*.pem*"]=crl/certs/
        ["*crl*nopass.pem*"]=crl/private/
    )
    for regexp in "${!certsmask[@]}"; do
        #printf 'Regexp %s is: %s\n' "$regexp" "${certsmask[$regexp]}"
        mkdir "${certsmask[$regexp]}" -p
        for f in $(find trustchain -name "$regexp"); do
            nf=$(echo $f | sed "s/.*\/\([^\/]*\)/${PREFIX}\1/g")
            mv $f "${certsmask[$regexp]}${nf}"
        done
    done
    cp trustchain/ca/index.txt ca/${PREFIX}index.txt
    cp trustchain/ca/index.txt.attr ca/${PREFIX}index.txt.attr
    cp trustchain/ca/intermediate/index.txt ca/${PREFIX}intermediate-index.txt
    cp trustchain/ca/intermediate/index.txt.attr ca/${PREFIX}intermediate-index.txt.attr
}

rm -rf trustchain ca client crl ocsp server
prime_dirs
trust_chain_gen "ca" "intermediate"
create_certificate_revocation_list
srv_gen_crt "server" "localhost"
srv_gen_crt "ocsp" "127.0.0.1"
C=400
while [ $C -le 550 ]; do
    usr_gen_crt "client-$C" "$C" "ocsp"
    let C=$C+1
done
usr_gen_crt "client-555" "5x5x5" "ocsp"
usr_gen_crt "client-666" "666" "ocsp"
usr_gen_crt "client-777" "777" "ocsp"
usr_gen_crt "client-888" "888" "ocsp"
usr_gen_crt "client-999" "9" "ocsp"
usr_gen_crt "client-10001" "10001" "ocsp" "1000042"
revoke_certificate "client-888"
create_certificate_revocation_list
archive_certs ""
rm -rf trustchain
prime_dirs
trust_chain_gen "ca" "intermediate"
create_certificate_revocation_list
srv_gen_crt "ocsp" "127.0.0.1"
usr_gen_crt "client" "111" "ocsp"
create_certificate_revocation_list
archive_certs "unknown-"
rm -rf trustchain
echo "Done."
