FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        heimdal-kdc \
    && rm -rf /var/lib/apt/lists/*

COPY tests/docker/kerberos/krb5.conf /etc/krb5.conf
COPY tests/docker/kerberos/kdc.conf /etc/krb5kdc/kdc.conf
COPY tests/docker/kerberos/kadm5.acl /etc/krb5kdc/kadm5.acl
COPY tests/docker/kdc-entrypoint.sh /usr/local/bin/nfsembed-kdc

RUN chmod 0755 /usr/local/bin/nfsembed-kdc

EXPOSE 88/tcp 88/udp

ENTRYPOINT ["/usr/local/bin/nfsembed-kdc"]
