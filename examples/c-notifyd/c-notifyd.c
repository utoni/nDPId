#include <dbus-1.0/dbus/dbus.h>
#include <signal.h>
#include <stdint.h>
#include <syslog.h>

#include "nDPIsrvd.h"
#include "utstring.h"
#include "utils.h"

struct flow_user_data
{
    nDPIsrvd_ull detected_risks;
};

enum dbus_level
{
    DBUS_LOW = 0,
    DBUS_NORMAL,
    DBUS_CRITICAL
};

static char const * const flow_severities[] = {"Low", "Medium", "High", "Severe", "Critical", "Emergency"};
static char const * const flow_breeds[] = {
    "Safe", "Acceptable", "Fun", "Unsafe", "Potentially Dangerous", "Tracker\\/Ads", "Dangerous", "Unrated", "???"};
static char const * const flow_categories[] = {"Unspecified",
                                               "Media",
                                               "VPN",
                                               "Email",
                                               "DataTransfer",
                                               "Web",
                                               "SocialNetwork",
                                               "Download",
                                               "Game",
                                               "Chat",
                                               "VoIP",
                                               "Database",
                                               "RemoteAccess",
                                               "Cloud",
                                               "Network",
                                               "Collaborative",
                                               "RPC",
                                               "Streaming",
                                               "System",
                                               "SoftwareUpdate",
                                               "Music",
                                               "Video",
                                               "Shopping",
                                               "Productivity",
                                               "FileSharing",
                                               "ConnCheck",
                                               "IoT-Scada",
                                               "VirtAssistant",
                                               "Cybersecurity",
                                               "AdultContent",
                                               "Mining",
                                               "Malware",
                                               "Advertisement",
                                               "Banned_Site",
                                               "Site_Unavailable",
                                               "Allowed_Site",
                                               "Antimalware",
                                               "Crypto_Currency"};

static uint8_t desired_flow_severities[nDPIsrvd_ARRAY_LENGTH(flow_severities)] = {};
static uint8_t desired_flow_breeds[nDPIsrvd_ARRAY_LENGTH(flow_breeds)] = {};
static uint8_t desired_flow_categories[nDPIsrvd_ARRAY_LENGTH(flow_categories)] = {};

static unsigned int id = 0;
static char const * const application = "nDPIsrvd.notifyd";

static int main_thread_shutdown = 0;

static char * pidfile = NULL;
static char * serv_optarg = NULL;

static void send_to_dbus(char const * const icon,
                         char const * const urgency,
                         enum dbus_level level,
                         char const * const summary,
                         char const * const body,
                         int timeout)
{
    DBusConnection * connection = dbus_bus_get(DBUS_BUS_SESSION, 0);
    DBusMessage * message = dbus_message_new_method_call("org.freedesktop.Notifications",
                                                         "/org/freedesktop/Notifications",
                                                         "org.freedesktop.Notifications",
                                                         "Notify");
    DBusMessageIter iter[4];
    dbus_message_iter_init_append(message, iter);
    dbus_message_iter_append_basic(iter, 's', &application);
    dbus_message_iter_append_basic(iter, 'u', &id);
    dbus_message_iter_append_basic(iter, 's', &icon);
    dbus_message_iter_append_basic(iter, 's', &summary);
    dbus_message_iter_append_basic(iter, 's', &body);
    dbus_message_iter_open_container(iter, 'a', "s", iter + 1);
    dbus_message_iter_close_container(iter, iter + 1);
    dbus_message_iter_open_container(iter, 'a', "{sv}", iter + 1);
    dbus_message_iter_open_container(iter + 1, 'e', 0, iter + 2);
    dbus_message_iter_append_basic(iter + 2, 's', &urgency);
    dbus_message_iter_open_container(iter + 2, 'v', "y", iter + 3);
    dbus_message_iter_append_basic(iter + 3, 'y', &level);
    dbus_message_iter_close_container(iter + 2, iter + 3);
    dbus_message_iter_close_container(iter + 1, iter + 2);
    dbus_message_iter_close_container(iter, iter + 1);
    dbus_message_iter_append_basic(iter, 'i', &timeout);
    dbus_connection_send(connection, message, 0);
    dbus_connection_flush(connection);
    dbus_message_unref(message);
    dbus_connection_unref(connection);

    id++;
}

static void notify(enum dbus_level level, char const * const summary, int timeout, char const * const body)
{
    send_to_dbus("dialog-information", "urgency", level, summary, body, timeout);
}

__attribute__((format(printf, 4, 5))) static void notifyf(
    enum dbus_level level, char const * const summary, int timeout, char const * const body_fmt, ...)
{
    va_list ap;
    char buf[BUFSIZ];

    va_start(ap, body_fmt);
    if (vsnprintf(buf, sizeof(buf), body_fmt, ap) > 0)
    {
        notify(level, summary, timeout, buf);
    }
    va_end(ap);
}

static ssize_t get_value_index(char const * const possible_values[],
                               size_t possible_values_size,
                               char const * const needle,
                               size_t needle_len)
{
    size_t i;

    for (i = 0; i < possible_values_size; ++i)
    {
        if (strncmp(needle, possible_values[i], needle_len) == 0)
        {
            break;
        }
    }

    if (i == possible_values_size)
    {
        return -1;
    }

    return i;
}

static void check_value(char const * const possible_values[],
                        size_t possible_values_size,
                        char const * const needle,
                        size_t needle_len)
{
    if (get_value_index(possible_values, possible_values_size, needle, needle_len) == -1)
    {
        syslog(LOG_DAEMON | LOG_ERR, "BUG: Unknown value: %.*s", (int)needle_len, needle);
        notifyf(DBUS_CRITICAL, "BUG", 5000, "Unknown value: %.*s", (int)needle_len, needle);
    }
}

static enum nDPIsrvd_callback_return notifyd_json_callback(struct nDPIsrvd_socket * const sock,
                                                           struct nDPIsrvd_instance * const instance,
                                                           struct nDPIsrvd_thread_data * const thread_data,
                                                           struct nDPIsrvd_flow * const flow)
{
    (void)instance;
    (void)thread_data;

    struct nDPIsrvd_json_token const * const flow_event_name = TOKEN_GET_SZ(sock, "flow_event_name");
    struct flow_user_data * flow_user_data = NULL;

    if (flow != NULL)
    {
        flow_user_data = (struct flow_user_data *)flow->flow_user_data;
    }

    if (TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detected") != 0 ||
        TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "detection-update") != 0 ||
        TOKEN_VALUE_EQUALS_SZ(sock, flow_event_name, "update") != 0)
    {
        struct nDPIsrvd_json_token const * const flow_risks = TOKEN_GET_SZ(sock, "ndpi", "flow_risk");
        struct nDPIsrvd_json_token const * current = NULL;
        int next_child_index = -1, desired_severity_found = 0;
        UT_string risks;

        utstring_init(&risks);

        if (flow_risks != NULL)
        {
            while ((current = nDPIsrvd_get_next_token(sock, flow_risks, &next_child_index)) != NULL)
            {
                nDPIsrvd_ull numeric_risk_value = (nDPIsrvd_ull)-1;
                size_t flow_risk_key_len = 0;
                char const * const flow_risk_key = TOKEN_GET_KEY(sock, current, &flow_risk_key_len);

                if (flow_risk_key == NULL || flow_risk_key_len == 0)
                {
                    continue;
                }

                if (str_value_to_ull(flow_risk_key, &numeric_risk_value) == CONVERSION_OK && flow_user_data != NULL &&
                    (flow_user_data->detected_risks & (1ull << numeric_risk_value)) == 0)
                {
                    flow_user_data->detected_risks |= (1ull << (numeric_risk_value - 1));

                    char flow_risk_sz[flow_risk_key_len + 1];
                    snprintf(flow_risk_sz, sizeof(flow_risk_sz), "%llu", numeric_risk_value);
                    size_t flow_risk_len = 0;
                    size_t flow_severity_len = 0;
                    char const * const flow_risk_str =
                        TOKEN_GET_VALUE(sock,
                                        TOKEN_GET_SZ(sock, "ndpi", "flow_risk", flow_risk_sz, "risk"),
                                        &flow_risk_len);
                    char const * const flow_severity_str =
                        TOKEN_GET_VALUE(sock,
                                        TOKEN_GET_SZ(sock, "ndpi", "flow_risk", flow_risk_sz, "severity"),
                                        &flow_severity_len);

                    if (flow_risk_str == NULL || flow_risk_len == 0 || flow_severity_str == NULL ||
                        flow_severity_len == 0)
                    {
                        continue;
                    }

                    ssize_t severity_index = get_value_index(flow_severities,
                                                             nDPIsrvd_ARRAY_LENGTH(flow_severities),
                                                             flow_severity_str,
                                                             flow_severity_len);
                    if (severity_index != -1 && desired_flow_severities[severity_index] != 0)
                    {
                        desired_severity_found = 1;
                    }
                    utstring_printf(&risks,
                                    "Risk: '%.*s'\n"
                                    "Severity: '%.*s'\n",
                                    (int)flow_risk_len,
                                    flow_risk_str,
                                    (int)flow_severity_len,
                                    flow_severity_str);
                    check_value(flow_severities,
                                nDPIsrvd_ARRAY_LENGTH(flow_severities),
                                flow_severity_str,
                                flow_severity_len);
                }
            }
        }

        {
            size_t flow_breed_len = 0;
            size_t flow_category_len = 0;
            char const * const flow_breed_str =
                TOKEN_GET_VALUE(sock, TOKEN_GET_SZ(sock, "ndpi", "breed"), &flow_breed_len);
            char const * const flow_category_str =
                TOKEN_GET_VALUE(sock, TOKEN_GET_SZ(sock, "ndpi", "category"), &flow_category_len);

            if (flow_breed_str != NULL && flow_breed_len != 0 && flow_category_str != NULL && flow_category_len != 0)
            {
                ssize_t breed_index =
                    get_value_index(flow_breeds, nDPIsrvd_ARRAY_LENGTH(flow_breeds), flow_breed_str, flow_breed_len);
                ssize_t category_index = get_value_index(flow_categories,
                                                         nDPIsrvd_ARRAY_LENGTH(flow_categories),
                                                         flow_category_str,
                                                         flow_category_len);

                if ((breed_index != -1 && desired_flow_breeds[breed_index] != 0) ||
                    (category_index != -1 && desired_flow_categories[category_index] != 0) ||
                    desired_severity_found != 0)
                {
                    notifyf(DBUS_CRITICAL,
                            "Flow Notification",
                            5000,
                            "Breed: '%.*s', Category: '%.*s'\n%s",
                            (int)flow_breed_len,
                            flow_breed_str,
                            (int)flow_category_len,
                            flow_category_str,
                            (utstring_len(&risks) > 0 ? utstring_body(&risks) : "No flow risks detected\n"));
                }

                check_value(flow_breeds, nDPIsrvd_ARRAY_LENGTH(flow_breeds), flow_breed_str, flow_breed_len);
                check_value(flow_categories,
                            nDPIsrvd_ARRAY_LENGTH(flow_categories),
                            flow_category_str,
                            flow_category_len);
            }
            else if (desired_severity_found != 0)
            {
                notifyf(DBUS_CRITICAL, "Risky Flow", 5000, "%s", utstring_body(&risks));
            }
        }

        utstring_done(&risks);
    }

    return CALLBACK_OK;
}

static void print_usage(char const * const arg0)
{
    static char const usage[] =
        "Usage: %s "
        "[-s host] [-C category...] [-B breed...] [-S severity...]\n\n"
        "\t-s\tDestination where nDPIsrvd is listening on.\n"
        "\t-C\tDesired nDPI category which fires a notificiation.\n"
        "\t  \tCan be specified multiple times.\n"
        "\t-B\tDesired nDPI breed which fires a notification.\n"
        "\t  \tCan be specified multiple times.\n"
        "\t-S\tDesired nDPI risk severity which fires a notification.\n"
        "\t  \tCan be specified multiple times.\n"
        "\n"
        "Possible values for `-C': %s\n"
        "Possible values for `-B': %s\n"
        "Possible values for `-S': %s\n"
        "\n";

    UT_string flow_categories_str, flow_breeds_str, flow_severities_str;
    utstring_init(&flow_categories_str);
    utstring_init(&flow_breeds_str);
    utstring_init(&flow_severities_str);
    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(flow_categories); ++i)
    {
        utstring_printf(&flow_categories_str, "%s, ", flow_categories[i]);
    }
    flow_categories_str.d[flow_categories_str.i - 2] = '\0';
    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(flow_breeds); ++i)
    {
        utstring_printf(&flow_breeds_str, "%s, ", flow_breeds[i]);
    }
    flow_breeds_str.d[flow_breeds_str.i - 2] = '\0';
    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(flow_severities); ++i)
    {
        utstring_printf(&flow_severities_str, "%s, ", flow_severities[i]);
    }
    flow_severities_str.d[flow_severities_str.i - 2] = '\0';
    fprintf(stderr,
            usage,
            arg0,
            utstring_body(&flow_categories_str),
            utstring_body(&flow_breeds_str),
            utstring_body(&flow_severities_str));
    utstring_done(&flow_severities_str);
    utstring_done(&flow_breeds_str);
    utstring_done(&flow_categories_str);
}

static int set_defaults(void)
{
    char const * const default_severities[] = {"High", "Severe", "Critical", "Emergency"};
    char const * const default_breeds[] = {"Unsafe", "Potentially Dangerous", "Dangerous", "Unrated"};
    char const * const default_categories[] = {"Mining", "Malware", "Banned_Site", "Crypto_Currency"};

    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(default_severities); ++i)
    {
        ssize_t index = get_value_index(flow_severities,
                                        nDPIsrvd_ARRAY_LENGTH(flow_severities),
                                        default_severities[i],
                                        strlen(default_severities[i]));
        if (index == -1)
        {
            return 1;
        }
        desired_flow_severities[index] = 1;
    }

    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(default_breeds); ++i)
    {
        ssize_t index = get_value_index(flow_breeds,
                                        nDPIsrvd_ARRAY_LENGTH(flow_breeds),
                                        default_breeds[i],
                                        strlen(default_breeds[i]));
        if (index == -1)
        {
            return 1;
        }
        desired_flow_breeds[index] = 1;
    }

    for (size_t i = 0; i < nDPIsrvd_ARRAY_LENGTH(default_categories); ++i)
    {
        ssize_t index = get_value_index(flow_categories,
                                        nDPIsrvd_ARRAY_LENGTH(flow_categories),
                                        default_categories[i],
                                        strlen(default_categories[i]));
        if (index == -1)
        {
            return 1;
        }
        desired_flow_categories[index] = 1;
    }

    return 0;
}

static int parse_options(int argc, char ** argv, struct nDPIsrvd_socket * const sock)
{
    int opt, force_defaults = 1;

    while ((opt = getopt(argc, argv, "hdp:s:C:B:S:")) != -1)
    {
        switch (opt)
        {
            case 'd':
                daemonize_enable();
                break;
            case 'p':
                free(pidfile);
                pidfile = strdup(optarg);
                break;
            case 's':
                free(serv_optarg);
                serv_optarg = strdup(optarg);
                break;
            case 'C':
            {
                ssize_t index =
                    get_value_index(flow_categories, nDPIsrvd_ARRAY_LENGTH(flow_categories), optarg, strlen(optarg));
                if (index == -1)
                {
                    fprintf(stderr, "Invalid argument for `-C': %s\n", optarg);
                    return 1;
                }
                else
                {
                    desired_flow_categories[index] = 1;
                }
                force_defaults = 0;
                break;
            }
            case 'B':
            {
                ssize_t index =
                    get_value_index(flow_breeds, nDPIsrvd_ARRAY_LENGTH(flow_breeds), optarg, strlen(optarg));
                if (index == -1)
                {
                    fprintf(stderr, "Invalid argument for `-B': %s\n", optarg);
                    return 1;
                }
                else
                {
                    desired_flow_breeds[index] = 1;
                }
                force_defaults = 0;
                break;
            }
            case 'S':
            {
                ssize_t index =
                    get_value_index(flow_severities, nDPIsrvd_ARRAY_LENGTH(flow_severities), optarg, strlen(optarg));
                if (index == -1)
                {
                    fprintf(stderr, "Invalid argument for `-S': %s\n", optarg);
                    return 1;
                }
                else
                {
                    desired_flow_severities[index] = 1;
                }
                force_defaults = 0;
                break;
            }
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (force_defaults != 0 && set_defaults() != 0)
    {
        fprintf(stderr, "%s\n", "BUG: Could not set default values.");
        syslog(LOG_DAEMON | LOG_ERR, "%s\n", "BUG: Could not set default values.");
        return 1;
    }

    if (serv_optarg == NULL)
    {
        serv_optarg = strdup(DISTRIBUTOR_UNIX_SOCKET);
    }

    if (nDPIsrvd_setup_address(&sock->address, serv_optarg) != 0)
    {
        syslog(LOG_DAEMON | LOG_ERR, "Could not parse address `%s'", serv_optarg);
        return 1;
    }

    if (optind < argc)
    {
        syslog(LOG_DAEMON | LOG_ERR, "%s", "Unexpected argument after options");
        return 1;
    }

    return 0;
}

static void sighandler(int signum)
{
    switch (signum)
    {
        case SIGINT:
            notify(DBUS_LOW, "nDPIsrvd-notifyd", 3000, "Received SIGINT, shutdown.");
            break;
        case SIGTERM:
            notify(DBUS_LOW, "nDPIsrvd-notifyd", 3000, "Received SIGTERM, shutdown.");
            break;
        default:
            notify(DBUS_LOW, "nDPIsrvd-notifyd", 3000, "Received unknown signal, shutdown.");
            break;
    }

    main_thread_shutdown++;
}

int main(int argc, char ** argv)
{
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGPIPE, SIG_IGN);

    openlog("nDPIsrvd-notifyd", LOG_CONS, LOG_DAEMON);

    struct nDPIsrvd_socket * sock =
        nDPIsrvd_socket_init(0, 0, 0, sizeof(struct flow_user_data), notifyd_json_callback, NULL, NULL);
    if (sock == NULL)
    {
        syslog(LOG_DAEMON | LOG_ERR, "%s", "nDPIsrvd socket memory allocation failed!");
        return 1;
    }

    if (parse_options(argc, argv, sock) != 0)
    {
        goto failure;
    }

    if (daemonize_with_pidfile(pidfile) != 0)
    {
        return 1;
    }

    int previous_connect_succeeded = 1;
    do
    {
        if (nDPIsrvd_connect(sock) != CONNECT_OK)
        {
            if (previous_connect_succeeded != 0)
            {
                notifyf(DBUS_CRITICAL, "nDPIsrvd-notifyd", 3000, "nDPIsrvd socket connect to %s failed!", serv_optarg);
                syslog(LOG_DAEMON | LOG_ERR, "nDPIsrvd socket connect to %s failed!", serv_optarg);
                previous_connect_succeeded = 0;
            }
            nDPIsrvd_socket_close(sock);
            sleep(1);
            continue;
        }
        previous_connect_succeeded = 1;

        if (nDPIsrvd_set_read_timeout(sock, 3, 0) != 0)
        {
            syslog(LOG_DAEMON | LOG_ERR, "nDPIsrvd set read timeout failed: %s", strerror(errno));
            goto failure;
        }

        notifyf(DBUS_NORMAL, "nDPIsrvd-notifyd", 3000, "Connected to '%s'", serv_optarg);
        syslog(LOG_DAEMON | LOG_NOTICE, "%s", "Initialization succeeded.");

        while (main_thread_shutdown == 0)
        {
            enum nDPIsrvd_read_return read_ret = nDPIsrvd_read(sock);
            if (errno == EINTR)
            {
                continue;
            }
            if (read_ret == READ_TIMEOUT)
            {
                continue;
            }
            if (read_ret != READ_OK)
            {
                break;
            }

            enum nDPIsrvd_parse_return parse_ret = nDPIsrvd_parse_all(sock);
            if (parse_ret != PARSE_NEED_MORE_DATA)
            {
                syslog(LOG_DAEMON | LOG_ERR,
                       "Could not parse json string %s: %.*s\n",
                       nDPIsrvd_enum_to_string(parse_ret),
                       nDPIsrvd_json_buffer_length(sock),
                       nDPIsrvd_json_buffer_string(sock));
                break;
            }
        }

        nDPIsrvd_socket_close(sock);
        notifyf(DBUS_NORMAL, "nDPIsrvd-notifyd", 3000, "Disconnected from '%s'.", serv_optarg);
    } while (main_thread_shutdown == 0);

failure:
    nDPIsrvd_socket_free(&sock);
    daemonize_shutdown(pidfile);
    closelog();

    return 0;
}
