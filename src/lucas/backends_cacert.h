/*
 * sotOs · LUCAS · CA-certificates VFS backend.
 *
 * Exposes /etc/ssl/cert.pem (the OpenSSL default trust store) as a read-only
 * regular file backed by the binstore blob "ca-certificates.crt".  Lets the
 * Tier-0e egress TLS client (busybox wget → openssl s_client, python ssl)
 * VERIFY real server certificates without --no-check-certificate.
 *
 * Mount prefix:        "/etc/ssl/cert.pem"  (longest-prefix beats the /etc union)
 * Single exposed file: "/etc/ssl/cert.pem"
 */

#ifndef LUCAS_BACKENDS_CACERT_H
#define LUCAS_BACKENDS_CACERT_H

#include <lucas/vfs.h>

/* Returns a vfs_mount_t with prefix "/etc/ssl/cert.pem" backed by binstore
 * "ca-certificates.crt". */
vfs_mount_t lucas_cacert_mount(void);

#endif /* LUCAS_BACKENDS_CACERT_H */
