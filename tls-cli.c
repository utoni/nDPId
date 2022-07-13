/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <errno.h>

#define CHECK(x) assert((x) >= 0)

#define MAX_BUF 1024
#define MSG "Hello TLS"

static int tcp_connect(void)
{
    const char * PORT = "5556";
    const char * SERVER = "127.0.0.1";
    int err, sd;
    struct sockaddr_in sa;

    /* connects to server
     */
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(atoi(PORT));
    inet_pton(AF_INET, SERVER, &sa.sin_addr);

    err = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
    if (err < 0)
    {
        fprintf(stderr, "Connect error\n");
        exit(1);
    }

    return sd;
}

static void tcp_close(int sd)
{
    shutdown(sd, SHUT_RDWR); /* no more receptions */
    close(sd);
}

int main(void)
{
    int ret, sd, ii;
    gnutls_session_t session;
    char buffer[MAX_BUF + 1], *desc;
    gnutls_datum_t out;
    int type;
    unsigned status;
    gnutls_certificate_credentials_t xcred;

    if (gnutls_check_version("3.4.6") == NULL)
    {
        fprintf(stderr, "GnuTLS 3.4.6 or later is required for this example\n");
        exit(1);
    }

    /* for backwards compatibility with gnutls < 3.3.0 */
    CHECK(gnutls_global_init());

    /* X509 stuff */
    CHECK(gnutls_certificate_allocate_credentials(&xcred));

    gnutls_certificate_set_x509_key_file(xcred, "client-cert.pem", "client-key.pem", GNUTLS_X509_FMT_PEM);

    CHECK(gnutls_certificate_set_x509_trust_file(xcred, "ca-cert.pem", GNUTLS_X509_FMT_PEM));

    /* Initialize TLS session */
    CHECK(gnutls_init(&session, GNUTLS_CLIENT));

    /* It is recommended to use the default priorities */
    CHECK(gnutls_set_default_priority(session));

    /* put the x509 credentials to the current session */
    CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred));

    sd = tcp_connect();

    gnutls_transport_set_int(session, sd);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Perform the TLS handshake */
    do
    {
        ret = gnutls_handshake(session);
    } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
    if (ret < 0)
    {
        if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
        {
            /* check certificate verification status */
            type = gnutls_certificate_type_get(session);
            status = gnutls_session_get_verify_cert_status(session);
            CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
            printf("cert verify output: %s\n", out.data);
            gnutls_free(out.data);
        }
        fprintf(stderr, "*** Handshake failed: %s\n", gnutls_strerror(ret));
        goto end;
    }
    else
    {
        desc = gnutls_session_get_desc(session);
        printf("- Session info: %s\n", desc);
        gnutls_free(desc);
    }

    /* send data */
    CHECK(gnutls_record_send(session, MSG, strlen(MSG)));

    ret = gnutls_record_recv(session, buffer, MAX_BUF);
    if (ret == 0)
    {
        printf("- Peer has closed the TLS connection\n");
        goto end;
    }
    else if (ret < 0 && gnutls_error_is_fatal(ret) == 0)
    {
        fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
    }
    else if (ret < 0)
    {
        fprintf(stderr, "*** Error: %s\n", gnutls_strerror(ret));
        goto end;
    }

    if (ret > 0)
    {
        printf("- Received %d bytes: ", ret);
        for (ii = 0; ii < ret; ii++)
        {
            fputc(buffer[ii], stdout);
        }
        fputs("\n", stdout);
    }

    CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));

end:

    tcp_close(sd);

    gnutls_deinit(session);

    gnutls_certificate_free_credentials(xcred);

    gnutls_global_deinit();

    return 0;
}
