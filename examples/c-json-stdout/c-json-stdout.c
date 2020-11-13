#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "jsmn/jsmn.h"

static char serv_listen_addr[INET_ADDRSTRLEN] = DISTRIBUTOR_HOST;
static uint16_t serv_listen_port = DISTRIBUTOR_PORT;

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in remote_addr = {};
    socklen_t remote_addrlen = sizeof(remote_addr);
    uint8_t buf[NETWORK_BUFFER_MAX_SIZE];
    size_t buf_used = 0;
    size_t json_start = 0;
    unsigned long long int json_bytes = 0;
    jsmn_parser parser;
    jsmntok_t tokens[128];

    if (sockfd < 0)
    {
        perror("socket");
        return 1;
    }

    remote_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, &serv_listen_addr[0], &remote_addr.sin_addr) != 1)
    {
        perror("inet_pton");
        return 1;
    }
    remote_addr.sin_port = htons(serv_listen_port);

    if (connect(sockfd, (struct sockaddr *)&remote_addr, remote_addrlen) != 0)
    {
        perror("connect");
        return 1;
    }

    while (1)
    {
        errno = 0;
        ssize_t bytes_read = read(sockfd, buf + buf_used, sizeof(buf) - buf_used);

        if (bytes_read <= 0 || errno != 0)
        {
            fprintf(stderr, "Remote end disconnected.\n");
            break;
        }

        buf_used += bytes_read;
        while (buf_used >= nDPIsrvd_JSON_BYTES + 1)
        {
            if (buf[nDPIsrvd_JSON_BYTES] != '{')
            {
                fprintf(stderr, "BUG: JSON invalid opening character: '%c'\n", buf[nDPIsrvd_JSON_BYTES]);
                exit(1);
            }

            char * json_str_start = NULL;
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
                fprintf(stderr, "BUG: Missing size before JSON string: \"%.*s\"\n", nDPIsrvd_JSON_BYTES, buf);
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

            if (buf[json_bytes - 1] != '}')
            {
                fprintf(stderr, "BUG: Invalid JSON string: %.*s\n", (int)json_bytes, buf);
                exit(1);
            }

            int r;
            jsmn_init(&parser);
            r = jsmn_parse(&parser,
                           (char *)(buf + json_start),
                           json_bytes - json_start,
                           tokens,
                           sizeof(tokens) / sizeof(tokens[0]));
            if (r < 0 || tokens[0].type != JSMN_OBJECT)
            {
                fprintf(stderr, "JSON parsing failed with return value %d at position %u\n", r, parser.pos);
                fprintf(stderr, "JSON string: '%.*s'\n", (int)(json_bytes - json_start), (char *)(buf + json_start));
                exit(1);
            }

            for (int i = 1; i < r; i++)
            {
                if (i % 2 == 1)
                {
                    printf("[%.*s : ", tokens[i].end - tokens[i].start, (char *)(buf + json_start) + tokens[i].start);
                }
                else
                {
                    printf("%.*s] ", tokens[i].end - tokens[i].start, (char *)(buf + json_start) + tokens[i].start);
                }
            }
            printf("EoF\n");

            memmove(buf, buf + json_bytes, buf_used - json_bytes);
            buf_used -= json_bytes;
            json_bytes = 0;
            json_start = 0;
        }
    }

    return 0;
}
