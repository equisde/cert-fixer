#!/system/bin/sh

# set up logging
exec > /data/local/tmp/cert-fixer.log
exec 2>&1

# help debugging (print each command to the terminal before executing)
set -x

# module root
MODDIR=${0%/*}

# set_context x y --> set the security context of y to match x
set_context() {
    [ "$(getenforce)" = "Enforcing" ] || return 0

    default_selinux_context=u:object_r:system_file:s0
    selinux_context=$(ls -Zd $1 | awk '{print $1}')

    if [ -n "$selinux_context" ] && [ "$selinux_context" != "?" ]; then
        chcon -R $selinux_context $2
    else
        chcon -R $default_selinux_context $2
    fi
}

echo "[i] looking for user certificates, ignoring versions"

# Read all the certificates ignoring the version.
# Later in the loop, the latest version of each certificate will be identified and copied to the system store
ls /data/misc/user/*/cacerts-added/* | grep -o -E '[0-9a-fA-F]{8}.[0-9]+$' | cut -d '.' -f1 | sort | uniq > /data/local/tmp/cert-fixer.certs-found

echo "[i] found $(cat /data/local/tmp/cert-fixer.certs-found | wc -l) certificates"

# Detect Android version by checking for APEX certificate directories
IS_A15_PLUS=false
IS_A14=false
# Android 15 and newer have a second cacerts location in the com.android.build APEX
if [ -d /apex/com.android.build/cacerts ]; then
    echo "[i] Android 15+ detected"
    IS_A15_PLUS=true
# Android 14 has cacerts in the com.android.conscrypt APEX
elif [ -d /apex/com.android.conscrypt/cacerts ]; then
    echo "[i] Android 14 detected"
    IS_A14=true
else
    echo "[i] Android < 14 detected"
fi

# Clone original CA certs into tmpfs based on detected version
if [ "$IS_A15_PLUS" = true ]; then
    echo "[i] Cloning Conscrypt CA certs to tmpfs"
    rm -rf /data/local/tmp/conscrypt-ca-copy
    mkdir -p /data/local/tmp/conscrypt-ca-copy
    mount -t tmpfs tmpfs /data/local/tmp/conscrypt-ca-copy
    cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/conscrypt-ca-copy/

    echo "[i] Cloning Build CA certs to tmpfs"
    rm -rf /data/local/tmp/build-ca-copy
    mkdir -p /data/local/tmp/build-ca-copy
    mount -t tmpfs tmpfs /data/local/tmp/build-ca-copy
    cp -f /apex/com.android.build/cacerts/* /data/local/tmp/build-ca-copy/

elif [ "$IS_A14" = true ]; then
    echo "[i] Cloning Conscrypt CA certs to tmpfs"
    rm -rf /data/local/tmp/conscrypt-ca-copy
    mkdir -p /data/local/tmp/conscrypt-ca-copy
    mount -t tmpfs tmpfs /data/local/tmp/conscrypt-ca-copy
    cp -f /apex/com.android.conscrypt/cacerts/* /data/local/tmp/conscrypt-ca-copy/
fi

echo "[i] entering loop for copying certificates to system store"
while read USER_CERT_HASH; do

    echo "[i] attempting to copy ${USER_CERT_HASH}"

    USER_CERT_FILE=$(ls /data/misc/user/*/cacerts-added/${USER_CERT_HASH}.* | (IFS=.; while read -r left right; do echo $right $left.$right; done) | sort -nr | (read -r left right; echo $right))

    echo "[i] latest version found: ${USER_CERT_FILE}"

    if ! [ -e "${USER_CERT_FILE}" ]; then
        echo "[e] error finding latest version of ${USER_CERT_HASH}"
        continue # Use continue instead of exit to allow other certs to be processed
    fi

    echo "[i] delete CAs removed by user or update"
    rm -f /data/misc/user/*/cacerts-removed/${USER_CERT_HASH}.*

    echo "[i] copy certificates to the old location and set the ownership and permissions"
    cp -f ${USER_CERT_FILE} ${MODDIR}/system/etc/security/cacerts/${USER_CERT_HASH}.0
    chown -R 0:0 ${MODDIR}/system/etc/security/cacerts
    chmod 644 ${MODDIR}/system/etc/security/cacerts/*
    set_context /system/etc/security/cacerts ${MODDIR}/system/etc/security/cacerts

    # Copy to temporary APEX directories if needed
    if [ "$IS_A15_PLUS" = true ]; then
        echo "[i] Copying cert to temporary APEX stores (A15+)"
        cp -f ${USER_CERT_FILE} /data/local/tmp/conscrypt-ca-copy/${USER_CERT_HASH}.0
        cp -f ${USER_CERT_FILE} /data/local/tmp/build-ca-copy/${USER_CERT_HASH}.0
    elif [ "$IS_A14" = true ]; then
        echo "[i] Copying cert to temporary APEX store (A14)"
        cp -f ${USER_CERT_FILE} /data/local/tmp/conscrypt-ca-copy/${USER_CERT_HASH}.0
    fi

done </data/local/tmp/cert-fixer.certs-found

# Finalize mounts for APEX directories
if [ "$IS_A15_PLUS" = true ]; then
    echo "[i] Finalizing mounts for Android 15+"

    # Prepare and mount Conscrypt CA store
    echo "[i] Preparing and mounting Conscrypt CA store"
    chown -R 0:0 /data/local/tmp/conscrypt-ca-copy
    set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/conscrypt-ca-copy
    mount --bind /data/local/tmp/conscrypt-ca-copy /apex/com.android.conscrypt/cacerts

    # Prepare and mount Build CA store
    echo "[i] Preparing and mounting Build CA store"
    chown -R 0:0 /data/local/tmp/build-ca-copy
    set_context /apex/com.android.build/cacerts /data/local/tmp/build-ca-copy
    mount --bind /data/local/tmp/build-ca-copy /apex/com.android.build/cacerts

    # Apply mounts to Zygote namespaces for both locations
    echo "[i] Applying mounts to Zygote namespaces"
    for pid in 1 $(pgrep zygote) $(pgrep zygote64); do
        nsenter --mount=/proc/${pid}/ns/mnt -- \
            /bin/mount --bind /data/local/tmp/conscrypt-ca-copy /apex/com.android.conscrypt/cacerts
        nsenter --mount=/proc/${pid}/ns/mnt -- \
            /bin/mount --bind /data/local/tmp/build-ca-copy /apex/com.android.build/cacerts
    done

    # Cleanup
    umount /data/local/tmp/conscrypt-ca-copy
    rmdir /data/local/tmp/conscrypt-ca-copy
    umount /data/local/tmp/build-ca-copy
    rmdir /data/local/tmp/build-ca-copy

elif [ "$IS_A14" = true ]; then
    echo "[i] Finalizing mount for Android 14"

    # Prepare and mount Conscrypt CA store
    echo "[i] Preparing and mounting Conscrypt CA store"
    chown -R 0:0 /data/local/tmp/conscrypt-ca-copy
    set_context /apex/com.android.conscrypt/cacerts /data/local/tmp/conscrypt-ca-copy
    mount --bind /data/local/tmp/conscrypt-ca-copy /apex/com.android.conscrypt/cacerts

    # Apply mounts to Zygote namespaces
    echo "[i] Applying mounts to Zygote namespaces"
    for pid in 1 $(pgrep zygote) $(pgrep zygote64); do
        nsenter --mount=/proc/${pid}/ns/mnt -- \
            /bin/mount --bind /data/local/tmp/conscrypt-ca-copy /apex/com.android.conscrypt/cacerts
    done

    # Cleanup
    umount /data/local/tmp/conscrypt-ca-copy
    rmdir /data/local/tmp/conscrypt-ca-copy
fi

echo "[i] Cert-Fixer execution completed"
