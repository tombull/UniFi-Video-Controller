#!/bin/bash

# Start up w/ the right umask
echo "[info] UMASK defined as '${UMASK}'." | ts '%Y-%m-%d %H:%M:%.S'
umask "${UMASK}"

# Options fed into unifi-video script
unifi_video_opts=""

# Graceful shutdown, used by trapping SIGTERM
function graceful_shutdown {
  echo -n "Stopping unifi-video... " | ts '%Y-%m-%d %H:%M:%.S'
  if /usr/sbin/unifi-video --nodetach stop; then
    echo "done."
    exit 0
  else
    echo "failed."
    exit 1
  fi
}

# Trap SIGTERM for graceful exit
trap graceful_shutdown SIGTERM

# Change user nobody's UID to custom or match unRAID.
echo "[info] PUID defined as '${PUID}'" | ts '%Y-%m-%d %H:%M:%.S'

# Set user unify-video to specified user id (non unique)
usermod -o -u "${PUID}" unifi-video &>/dev/null

# Change group users to GID to custom or match unRAID.
echo "[info] PGID defined as '${PGID}'" | ts '%Y-%m-%d %H:%M:%.S'

# Set group users to specified group id (non unique)
groupmod -o -g "${PGID}" unifi-video &>/dev/null

# Create logs directory
mkdir -p /var/lib/unifi-video/logs

# check for presence of perms file, if it exists then skip setting
# permissions, otherwise recursively set on volume mappings for host
if [[ ! -f "/var/lib/unifi-video/perms.txt" ]]; then
  echo "[info] No perms.txt found, setting ownership and permissions recursively on videos." | ts '%Y-%m-%d %H:%M:%.S'

  volumes=( "/var/lib/unifi-video" )

  # Set user and group ownership of volumes.
  if ! chown -R "${PUID}":"${PGID}" "${volumes[@]}"; then
    echo "[warn] Unable to chown ${volumes[*]}." | ts '%Y-%m-%d %H:%M:%.S'
  fi

  # Check for umask 002, set permissions to 775 folders and 664 files.
  if [[ "${UMASK}" -eq 002 ]]; then
    if ! chmod -R a=,a+rX,u+w,g+w "${volumes[@]}"; then
      echo "[warn] Unable to chmod ${volumes[*]}." | ts '%Y-%m-%d %H:%M:%.S'
    fi
  fi

  # Check for umask 022, set permissions to 755 folders and 644 files.
  if [[ "${UMASK}" -eq 022 ]]; then
    if ! chmod -R a=,a+rX,u+w "${volumes[@]}"; then
      echo "[warn] Unable to chmod ${volumes[*]}." | ts '%Y-%m-%d %H:%M:%.S'
    fi
  fi

  # Warn when neither umask 002 or 022 is set.
  if [[ "${UMASK}" -ne 002 ]] && [[ "${UMASK}" -ne 022 ]]; then
    echo "[warn] Umask not set to 002 or 022, skipping chmod." | ts '%Y-%m-%d %H:%M:%.S'
  fi

  echo "This file prevents permissions from being applied/re-applied to /config, if you want to reset permissions then please delete this file and restart the container." > /var/lib/unifi-video/perms.txt
else
  echo "[info] File perms.txt blocks chown/chmod of videos." | ts '%Y-%m-%d %H:%M:%.S'
fi

log() {
    echo "$(date +"[%Y-%m-%d %T,%3N]") <run.sh> $*"
}

if [[ ! -d "${CERTDIR}" || ! -f "${CERTDIR}/${CERTNAME}" ]]; then
    exit 0
fi

log 'Cert directory found. Checking Certs'

if `md5sum -c "${CERTDIR}/${CERTNAME}.md5" &>/dev/null`; then
    log "Cert has not changed, not updating controller."
    exit 0
else
    if [ ! -e "/usr/lib/unifi-video/data/keystore" ]; then
        log "WARN: Missing keystore, creating a new one"

        if [ ! -d "/usr/lib/unifi-video/data" ]; then
            log "Missing data directory, creating..."
            mkdir "/usr/lib/unifi-video/data"
        fi

        keytool -genkey -keyalg RSA -alias airvision -keystore "/usr/lib/unifi-video/data/keystore" \
            -storepass ubiquiti -keypass ubiquiti -validity 1825 \
            -keysize 4096 -dname "cn=UniFi"
    fi

    TEMPFILE=$(mktemp)
    TMPLIST="${TEMPFILE}"
    CERTTEMPFILE=$(mktemp)
    TMPLIST+=" ${CERTTEMPFILE}"
    CERTURI=$(openssl x509 -noout -ocsp_uri -in "${CERTDIR}/${CERTNAME}")
    # Identrust cross-signed CA cert needed by the java keystore for import.
    # Can get original here: https://www.identrust.com/certificates/trustid/root-download-x3.html
    cat > "${CERTTEMPFILE}" <<'_EOF'
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
_EOF

    log "Cert has changed, updating controller..."
    md5sum "${CERTDIR}/${CERTNAME}" > "${CERTDIR}/${CERTNAME}.md5"
    log "Using openssl to prepare certificate..."
    CHAIN=$(mktemp)
    TMPLIST+=" ${CHAIN}"

    if [[ "${CERTURI}" == *"letsencrypt"* && "$CERT_IS_CHAIN" == "true" ]]; then
        awk 1 "${CERTTEMPFILE}" "${CERTDIR}/${CERTNAME}" >> "${CHAIN}"
    elif [[ "${CERTURI}" == *"letsencrypt"* ]]; then
        awk 1 "${CERTTEMPFILE}" "${CERTDIR}/chain.pem" "${CERTDIR}/${CERTNAME}" >> "${CHAIN}"
    elif [[ -f "${CERTDIR}/ca.pem" ]]; then
        awk 1 "${CERTDIR}/ca.pem" "${CERTDIR}/chain.pem" "${CERTDIR}/${CERTNAME}" >> "${CHAIN}"
    else
        awk 1 "${CERTDIR}/chain.pem" "${CERTDIR}/${CERTNAME}" >> "${CHAIN}"
    fi
   openssl pkcs12 -export  -passout pass:ubiquiti \
        -in "${CHAIN}" \
        -inkey "${CERTDIR}/${CERT_PRIVATE_NAME}" \
        -out "${TEMPFILE}" -name airvision
    log "Removing existing certificate from Unifi protected keystore..."
    keytool -delete -alias airvision -keystore "/usr/lib/unifi-video/data/keystore" \
        -deststorepass ubiquiti
    log "Inserting certificate into Unifi keystore..."
    keytool -trustcacerts -importkeystore \
        -deststorepass ubiquiti \
        -destkeypass ubiquiti \
        -destkeystore "/usr/lib/unifi-video/data/keystore" \
        -srckeystore "${TEMPFILE}" -srcstoretype PKCS12 \
        -srcstorepass ubiquiti \
        -alias airvision
    log "Cleaning up temp files"
    for file in ${TMPLIST}; do
        rm -f "${file}"
    done
    log "Done!"
fi




confSet () {
  file=$1
  key=$2
  value=$3
  if [ "$newfile" != true ] && grep -q "^${key} *=" "$file"; then
    ekey=$(echo "$key" | sed -e 's/[]\/$*.^|[]/\\&/g')
    evalue=$(echo "$value" | sed -e 's/[\/&]/\\&/g')
    sed -i "s/^\(${ekey}\s*=\s*\).*$/\1${evalue}/" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

confFile="/var/lib/unifi-video/system.properties"
if [ -e "$confFile" ]; then
  newfile=false
else
  newfile=true
fi

declare -A settings

if ! [[ -z "$UNIFI_VIDEO_HTTP_PORT"  ]]; then
  settings["app.http.port"]="$UNIFI_VIDEO_HTTP_PORT"
fi

if ! [[ -z "$UNIFI_VIDEO_HTTPS_PORT"  ]]; then
  settings["app.https.port"]="$UNIFI_VIDEO_HTTPS_PORT"
fi

if ! [[ -z "$UNIFI_VIDEO_LIVEFLV_PORT"  ]]; then
  settings["app.liveflv.port"]="$UNIFI_VIDEO_LIVEFLV_PORT"
fi

if ! [[ -z "$UNIFI_VIDEO_LIVEWS_PORT"  ]]; then
  settings["app.livews.port"]="$UNIFI_VIDEO_LIVEWS_PORT"
fi

if ! [[ -z "$UNIFI_VIDEO_LIVEWSS_PORT"  ]]; then
  settings["app.livewss.port"]="$UNIFI_VIDEO_LIVEWSS_PORT"
fi

for key in "${!settings[@]}"; do
  confSet "$confFile" "$key" "${settings[$key]}"
done

if [ "${BIND_PRIV}" == "true" ]; then
	if setcap 'cap_net_bind_service=+ep' "${JAVA_HOME}/jre/bin/java"; then
		sleep 1
	else
		log "ERROR: setcap failed, can not continue"
		log "ERROR: You may either launch with -e BIND_PRIV=false and only use ports >1024"
		log "ERROR: or run this container as root"
		exit 1
	fi
fi

# No debug mode set via env, default to off
if [[ -z ${DEBUG} ]]; then
  DEBUG=0
fi

# Run with --debug if DEBUG=1
if [[ ${DEBUG} -eq 1 ]]; then
  echo "[debug] Running unifi-video service with --debug." | ts '%Y-%m-%d %H:%M:%.S'
  unifi_video_opts="--debug"
fi

# Run the unifi-video daemon the unifi-video way
echo -n "Starting unifi-video... " | ts '%Y-%m-%d %H:%M:%.S'
if /usr/sbin/unifi-video "${unifi_video_opts}" start; then
  echo "done."
else
  echo "failed."
  exit 1
fi

# Wait for mongodb to come online.
echo -n "Waiting for mongodb to come online..." | ts '%Y-%m-%d %H:%M:%.S'
while ! mongo --quiet localhost:7441 --eval "{ ping: 1}" > /dev/null 2>&1; do
  sleep 2
  echo -n "."
done
echo " done."

# Get the current featureCompatibilityVersion
MONGO_FEATURE_COMPATIBILITY_VERSION=$( mongo --quiet --eval "db.adminCommand( { getParameter: 1, featureCompatibilityVersion: 1 } )" localhost:7441 | jq -r .featureCompatibilityVersion.version )

# Update db to 3.4 features
if mongo --version 2>&1 | grep -q "v3.4"; then
  if [[ "${MONGO_FEATURE_COMPATIBILITY_VERSION}" != "3.4" ]]; then
    echo -n "Found FeatureCompatibilityVersion ${MONGO_FEATURE_COMPATIBILITY_VERSION}, setting to 3.4..." | ts '%Y-%m-%d %H:%M:%.S'
    if mongo --quiet --eval 'db.adminCommand( { setFeatureCompatibilityVersion: "3.4" } )' localhost:7441 > /dev/null 2>&1; then
      echo " done."
    else
      echo " failed."
    fi
  fi
fi

# Update db to 3.6 features
if mongo --version 2>&1 | grep -q "v3.6"; then
  if [[ "${MONGO_FEATURE_COMPATIBILITY_VERSION}" != "3.6" ]]; then
    echo -n "Found FeatureCompatibilityVersion ${MONGO_FEATURE_COMPATIBILITY_VERSION}, setting to 3.6..." | ts '%Y-%m-%d %H:%M:%.S'
    if mongo --quiet --eval 'db.adminCommand( { setFeatureCompatibilityVersion: "3.6" } )' localhost:7441 > /dev/null 2>&1; then
      echo " done."
    else
      echo " failed."
    fi
  fi
fi

# Update db to 4.0 features
if mongo --version 2>&1 | grep -q "v4.0"; then
  if [[ "${MONGO_FEATURE_COMPATIBILITY_VERSION}" != "4.0" ]]; then
    echo -n "Found FeatureCompatibilityVersion ${MONGO_FEATURE_COMPATIBILITY_VERSION}, setting to 4.0..." | ts '%Y-%m-%d %H:%M:%.S'
    if mongo --quiet --eval 'db.adminCommand( { setFeatureCompatibilityVersion: "4.0" } )' localhost:7441 > /dev/null 2>&1; then
      echo " done."
    else
      echo " failed."
    fi
  fi
fi

# Loop while we wait for shutdown trap
while true; do
  # When --tmpfs is used, container restarts cause these folders to go missing.
  # See issue #178 for details.
  if [[ ! -d /var/cache/unifi-video/exports ]]; then
    echo -n "Re-creating and setting ownership/permissions on /var/cache/unifi-video/exports... "
    mkdir -p /var/cache/unifi-video/exports
    chown unifi-video:unifi-video /var/cache/unifi-video/exports
    chmod 700 /var/cache/unifi-video/exports
    echo "done."
  fi

  if [[ ! -d /var/cache/unifi-video/hls ]]; then
    echo -n "Re-creating and setting ownership/permissions on /var/cache/unifi-video/hls... "
    mkdir -p /var/cache/unifi-video/hls
    chown unifi-video:unifi-video /var/cache/unifi-video/hls
    chmod 775 /var/cache/unifi-video/hls
    echo "done."
  fi
  sleep 5
done
