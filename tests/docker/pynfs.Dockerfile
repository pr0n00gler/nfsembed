FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef

ARG PYNFS_REPOSITORY=https://github.com/kofemann/pynfs.git
ARG PYNFS_REF=cd4701827a8261fedbfb4c6e39029fb9671321a6

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        git \
        krb5-user \
        libkrb5-dev \
        make \
        python3 \
        python3-dev \
        python3-gssapi \
        python3-ply \
        python3-setuptools \
        swig \
    && rm -rf /var/lib/apt/lists/*

COPY tests/docker/check-pynfs-client.sh /usr/local/bin/check-pynfs-client
COPY tests/docker/pynfs-lock24-rfc7530.patch /usr/local/share/pynfs-lock24-rfc7530.patch

RUN chmod 0755 /usr/local/bin/check-pynfs-client

RUN git clone --filter=blob:none --no-checkout "${PYNFS_REPOSITORY}" /opt/pynfs \
    && git -C /opt/pynfs checkout --detach "${PYNFS_REF}" \
    && test "$(git -C /opt/pynfs rev-parse HEAD)" = "${PYNFS_REF}" \
    && git -C /opt/pynfs apply --check /usr/local/share/pynfs-lock24-rfc7530.patch \
    && git -C /opt/pynfs apply /usr/local/share/pynfs-lock24-rfc7530.patch \
    && printf '%s\n' "${PYNFS_REF}" > /opt/pynfs/PINNED_COMMIT \
    && cd /opt/pynfs \
    && python3 ./setup.py build_ext --inplace \
    && check-pynfs-client /opt/pynfs

COPY tests/docker/kerberos/krb5.conf /etc/krb5.conf
COPY tests/docker/run-pynfs.sh /usr/local/bin/run-pynfs

RUN chmod 0755 /usr/local/bin/run-pynfs

WORKDIR /opt/pynfs/nfs4.0

ENTRYPOINT ["/usr/local/bin/run-pynfs"]
