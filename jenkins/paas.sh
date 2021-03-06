#!/usr/bin/env bash

set -eu

PN_PROJECT_DIR=$(pwd)
PKI_OUTPUT_DIR="$PN_PROJECT_DIR/paas_pki"

. ./jenkins/login_to_paas.sh

# Download xmlsectool
XMLSECTOOL_URL="http://shibboleth.net/downloads/tools/xmlsectool/latest/xmlsectool-2.0.0-bin.zip"
XMLSECTOOL_DIR="xmlsectool-2.0.0"
wget "$XMLSECTOOL_URL"
unzip "${XMLSECTOOL_DIR}-bin.zip"

# Generate PKI
pushd pki
  bundle install
  JAVA_HOME=${JAVA_HOME:-/usr/lib/jvm/default-java} bundle exec generate \
    --hub-entity-id "https://dev-hub.local" \
    --idp-entity-id "http://stub_idp.acme.org/stub-idp-demo/SSO/POST" \
    --proxy-node-entity-id "https://verify-eidas-notification-metadata.cloudapps.digital/metadata_for_connector_node.xml" \
    --hub-response-url "https://verify-eidas-notification-proxy-node.cloudapps.digital/SAML2/SSO/Response/POST" \
    --idp-sso-url "https://verify-eidas-notification-stub-idp.cloudapps.digital/stub-idp-demo/SAML2/SSO" \
    --proxy-sso-url "https://verify-eidas-notification-proxy-node.cloudapps.digital/SAML2/SSO/POST" \
    --manifests \
    --xmlsectool "${PN_PROJECT_DIR}/${XMLSECTOOL_DIR}/xmlsectool.sh" \
    "${PKI_OUTPUT_DIR}"
popd

mkdir -p logs

# Update metadata
(cp "$PKI_OUTPUT_DIR"/*.xml metadata/
pushd metadata
  cf push
popd
) >logs/metadata_paas_deploy.log 2>&1 &

# Deploy Stub IDP
(rm -rf ida-stub-idp
git clone git@github.com:alphagov/ida-stub-idp
pushd ida-stub-idp
  cp "$PKI_OUTPUT_DIR/stub_idp.manifest.yml" manifest.yml
  ./gradlew -x test distZip -PincludeDirectories="$PN_PROJECT_DIR/stub-idp/resources"

  # Setup Stub IDP DB
  cf bind-service verify-eidas-notification-stub-idp ida-stub-idp-db
  LOCAL_DB_URI="$(cf env verify-eidas-notification-stub-idp | grep -o '"jdbc:postgresql://[^"]*' | tr -d '"' |sed 's/\\u0026/\&/g')"
  cf set-env verify-eidas-notification-stub-idp DB_URI "$LOCAL_DB_URI"
  cf push
popd
rm -rf ida-stub-idp
) >logs/stub_idp_paas_deploy.log 2>&1 &

(cp "$PKI_OUTPUT_DIR/proxy_node.manifest.yml" manifest.yml
./gradlew -x test distZip
cf push
) >logs/proxy_node_paas_deploy.log 2>&1 &

wait

./jenkins/acceptance-test.sh
