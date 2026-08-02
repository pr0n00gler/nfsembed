#!/bin/sh
set -eu

realm=${KRB5_REALM:-NFSEMBED.TEST}
nfs_principal=${KRB5_NFS_PRINCIPAL:-nfs/server.nfsembed.test}
client_principal=${KRB5_CLIENT_PRINCIPAL:-client}
configuration=${KRB5_KDC_PROFILE:-/etc/krb5kdc/kdc.conf}
keytab_directory=/run/nfsembed-kdc

install -d -m 0700 /var/lib/krb5kdc "$keytab_directory"

if ! kadmin --local --realm="$realm" --config-file="$configuration" \
  get "krbtgt/$realm@$realm" >/dev/null 2>&1
then
  kadmin --local --realm="$realm" --config-file="$configuration" \
    init --realm-max-ticket-life=1h --realm-max-renewable-life=2h "$realm"
fi

ensure_principal() {
  principal=$1
  if ! kadmin --local --realm="$realm" --config-file="$configuration" \
    get "$principal@$realm" >/dev/null 2>&1
  then
    kadmin --local --realm="$realm" --config-file="$configuration" \
      add --random-key --use-defaults "$principal@$realm"
  fi
}

ensure_principal "$nfs_principal"
ensure_principal "$client_principal"

rm -f "$keytab_directory/nfs.keytab" "$keytab_directory/client.keytab"
kadmin --local --realm="$realm" --config-file="$configuration" \
  ext_keytab --keytab="$keytab_directory/nfs.keytab" "$nfs_principal@$realm"
kadmin --local --realm="$realm" --config-file="$configuration" \
  ext_keytab --keytab="$keytab_directory/client.keytab" "$client_principal@$realm"
chmod 0600 "$keytab_directory/nfs.keytab" "$keytab_directory/client.keytab"

exec /usr/lib/heimdal-servers/kdc --config-file="$configuration" --ports=88
