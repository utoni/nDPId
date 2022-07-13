/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <assert.h>

#define CAFILE "ca-cert.pem"
#define KEYFILE "server-key.pem"
#define CERTFILE "server-cert.pem"
#define CRLFILE "crl.pem"

#define CHECK(x) assert((x) >= 0)
#define LOOP_CHECK(rval, cmd)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        rval = cmd;                                                                                                    \
    } while (rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)

#define MAX_BUF 16
#define PORT 5556 /* listen to 5556 port */

int main(void)
{
    int listen_sd;
    int sd, ret;
    gnutls_certificate_credentials_t x509_cred;
    gnutls_priority_t priority_cache;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    socklen_t client_len;
    char topbuf[512];
    gnutls_session_t session;
    char buffer[MAX_BUF + 1];
    int optval = 1;

    /* for backwards compatibility with gnutls < 3.3.0 */
    CHECK(gnutls_global_init());

    CHECK(gnutls_certificate_allocate_credentials(&x509_cred));
    CHECK(gnutls_certificate_set_x509_crl_file(x509_cred, CRLFILE, GNUTLS_X509_FMT_PEM));
    CHECK(gnutls_certificate_set_x509_key_file(x509_cred, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM));
    CHECK(gnutls_certificate_set_x509_trust_file(x509_cred, CAFILE, GNUTLS_X509_FMT_PEM));
    CHECK(gnutls_priority_init(&priority_cache, NULL, NULL));

#if GNUTLS_VERSION_NUMBER >= 0x030506
    /* only available since GnuTLS 3.5.6, on previous versions see
     * gnutls_certificate_set_dh_params(). */
    gnutls_certificate_set_known_dh_params(x509_cred, GNUTLS_SEC_PARAM_HIGH);
#endif

    /* Socket operations */
    listen_sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa_serv, '\0', sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(PORT); /* Server Port number */

    setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(int));
    bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
    listen(listen_sd, 1024);

    printf("Server ready. Listening to port '%d'.\n", PORT);

    client_len = sizeof(sa_cli);
    for (;;)
    {
        CHECK(gnutls_init(&session, GNUTLS_SERVER));
        CHECK(gnutls_priority_set(session, priority_cache));
        CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));
        gnutls_session_set_verify_cert(session, NULL, 0);
        gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
        gnutls_certificate_send_x509_rdn_sequence(session, 1);
        gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);

        printf("- connection from %s, port %d\n",
               inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf, sizeof(topbuf)),
               ntohs(sa_cli.sin_port));

        gnutls_transport_set_int(session, sd);

        LOOP_CHECK(ret, gnutls_handshake(session));
        if (ret < 0)
        {
            close(sd);
            gnutls_deinit(session);
            fprintf(stderr, "*** Handshake has failed (%s)\n", gnutls_strerror(ret));
            continue;
        }
        printf("- Handshake was completed\n");

        for (;;)
        {
            LOOP_CHECK(ret, gnutls_record_recv(session, buffer, MAX_BUF));

            if (ret == 0)
            {
                printf("- Peer has closed the GnuTLS connection\n");
                break;
            }
            else if (ret < 0 && gnutls_error_is_fatal(ret) == 0)
            {
                fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
            }
            else if (ret < 0)
            {
                fprintf(stderr,
                        "\n*** Received corrupted "
                        "data(%d). Closing the connection.\n",
                        ret);
                break;
            }
            else if (ret > 0 && ret < MAX_BUF - 1)
            {
                buffer[ret] = '$';
                CHECK(gnutls_record_send(session, buffer, ret + 1));
            }
        }
        LOOP_CHECK(ret, gnutls_bye(session, GNUTLS_SHUT_WR));

        close(sd);
        gnutls_deinit(session);
    }
    close(listen_sd);

    gnutls_certificate_free_credentials(x509_cred);
    gnutls_priority_deinit(priority_cache);

    gnutls_global_deinit();

    return 0;
}
