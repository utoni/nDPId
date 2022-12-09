#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "config.h"

#include <glib.h>
#include <librdkafka/rdkafka.h>

//#include "common.c"

static void dr_msg_cb (rd_kafka_t *kafka_handle,
                       const rd_kafka_message_t *rkmessage,
                       void *opaque) {
    if (rkmessage->err) {
        g_error("Message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
    }
}

int main(int argc, char ** argv)
{
    const char usage[] =
        "Usage: nDPIsrvd-kafka -b broker -t topic\n"
        "\t-b\tBroker server list (each is ip:port or name:port).\n"
        "\t-t\tTopic name.\n";
    int opt;
    char *broker = NULL, *topic = NULL;
    while ((opt = getopt(argc, argv, "hb:t:")) != -1)
    {
        switch (opt)
        {
            case 'b':
                free(broker);
                broker = strdup(optarg);
                break;
            case 't':
                free(topic);
                topic = strdup(optarg);
                break;
            default:
                printf("%s", usage);
                free(broker);
                free(topic);
                return 1;
        }
    }

    if (broker == NULL)
    {
        fprintf(stderr, "Broker server is not assigned.\n");
        exit(1);
    }

    if (topic == NULL)
    {
        fprintf(stderr, "Topic is not assigned.\n");
        exit(1);
    }

    if (argc > optind)
    {
        fprintf(stderr, "Too many arguments.\n");
        exit(1);
    }

    char errstr[512];
    rd_kafka_conf_t *conf = rd_kafka_conf_new();
    if (rd_kafka_conf_set(conf, "bootstrap.servers", broker, errstr,
                          sizeof(errstr)) != RD_KAFKA_CONF_OK)
    {
        g_error("%s", errstr);
        exit(1);
    }

    rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

    rd_kafka_t *rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk)
    {
        g_error("Failed to create new producer: %s", errstr);
        exit(1);
    }
    conf = NULL;

    rd_kafka_topic_t *rkt = rd_kafka_topic_new(rk, topic, NULL);
    if (!rkt)
    {
        g_error("Failed to create new topic: %s", errstr);
        exit(1);
    }

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DISTRIBUTOR_UNIX_SOCKET, sizeof(addr.sun_path) - 1);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) != 0)
    {
        perror("connect");
        exit(1);
    }

    uint8_t buf[NETWORK_BUFFER_MAX_SIZE];
    size_t buf_used = 0;
    ssize_t bytes_read;
    char *json_str_start;
    unsigned long long int json_bytes = 0;
    size_t json_start = 0;
    rd_kafka_resp_err_t err;
    while (1)
    {
        errno = 0;
        bytes_read = read(sockfd, buf + buf_used, sizeof(buf) - buf_used);

        if (bytes_read <= 0 || errno != 0)
        {
            fprintf(stderr, "Remote end disconnected.\n");
            break;
        }

        buf_used += bytes_read;
        while (buf_used >= NETWORK_BUFFER_LENGTH_DIGITS + 1)
        {
            if (buf[NETWORK_BUFFER_LENGTH_DIGITS] != '{')
            {
                fprintf(stderr, "BUG: JSON invalid opening character: '%c'\n", buf[NETWORK_BUFFER_LENGTH_DIGITS]);
                exit(1);
            }

            json_str_start = NULL;
            json_bytes = strtoull((char *)buf, &json_str_start, 10);
            json_bytes += (uint8_t *)json_str_start - buf;
            json_start = (uint8_t *)json_str_start - buf;

            if (errno == ERANGE)
            {
                fprintf(stderr, "BUG: Size of JSON exceeds limit\n");
                exit(1);
            }
            if ((uint8_t *)json_str_start == buf)
            {
                fprintf(stderr, "BUG: Missing size before JSON string: \"%.*s\"\n", NETWORK_BUFFER_LENGTH_DIGITS, buf);
                exit(1);
            }
            if (json_bytes > sizeof(buf))
            {
                fprintf(stderr, "BUG: JSON string too big: %llu > %zu\n", json_bytes, sizeof(buf));
                exit(1);
            }
            if (json_bytes > buf_used)
            {
                break;
            }

            if (buf[json_bytes - 2] != '}' ||
                buf[json_bytes - 1] != '\n')
            {
                fprintf(stderr, "BUG: Invalid JSON string: \"%.*s\"\n", (int)json_bytes, buf);
                exit(1);
            }

            err = rd_kafka_produce(rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                                   buf+json_start, json_bytes-json_start, NULL, 0, NULL);
            if (err)
            {
                g_error("Failed to produce one message: %s", rd_kafka_err2str(err));
                exit(1);
            } else {
                 rd_kafka_flush(rk, 2 * 1000);
                g_message("Produced one message: %.*s", (int)(json_bytes-json_start), buf+json_start);
            }

            memmove(buf, buf + json_bytes, buf_used - json_bytes);
            buf_used -= json_bytes;
            json_bytes = 0;
            json_start = 0;
        } // end while
    } // end while (1)

    rd_kafka_topic_destroy(rkt);
    rd_kafka_destroy(rk);

    return 0;
}
