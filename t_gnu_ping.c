#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <netdb.h> // for getprotobyname
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PING_INTERVAL 1
#define PING_CKTABSIZE 128

#define PEV_RESPONSE 0
#define PEV_DUPLICATE 1
#define PEV_NOECHO 2

#define PING_TIMING(s) (s >= PING_HEADER_LEN)
#define PING_HEADER_LEN sizeof(struct timeval)
#define PING_DATALEN (64 - PING_HEADER_LEN) /* default data length */

#define _PING_BUFLEN(p) ((p)->ping_datalen + sizeof(icmphdr_t))

#define _C_BIT(p, bit) (p)->ping_cktab[(bit) >> 3] /* byte in ck array */
#define _C_MASK(bit) (1 << ((bit)&0x07))
#define _PING_SET(p, bit) (_C_BIT(p, bit) |= _C_MASK(bit))
#define _PING_CLR(p, bit) (_C_BIT(p, bit) &= (~_C_MASK(bit)))
#define _PING_TST(p, bit) (_C_BIT(p, bit) & _C_MASK(bit))

#define MAXWAIT 10 /* max seconds to wait for response */

#define OPT_FLOOD 0x001
#define OPT_INTERVAL 0x002
#define OPT_NUMERIC 0x004
#define OPT_QUIET 0x008
#define OPT_RROUTE 0x010
#define OPT_VERBOSE 0x020

#define ICMP_ECHOREPLY 0    /* Echo Reply */
#define ICMP_DEST_UNREACH 3 /* Destination Unreachable */
/* Codes for ICMP_DEST_UNREACH. */
#define ICMP_NET_UNREACH 0  /* Network Unreachable */
#define ICMP_HOST_UNREACH 1 /* Host Unreachable */
#define ICMP_PROT_UNREACH 2 /* Protocol Unreachable */
#define ICMP_PORT_UNREACH 3 /* Port Unreachable */
#define ICMP_FRAG_NEEDED 4  /* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED 5    /* Source Route failed */
#define ICMP_NET_UNKNOWN 6
#define ICMP_HOST_UNKNOWN 7
#define ICMP_HOST_ISOLATED 8
#define ICMP_NET_ANO 9
#define ICMP_HOST_ANO 10
#define ICMP_NET_UNR_TOS 11
#define ICMP_HOST_UNR_TOS 12
#define ICMP_PKT_FILTERED 13   /* Packet filtered */
#define ICMP_PREC_VIOLATION 14 /* Precedence violation */
#define ICMP_PREC_CUTOFF 15    /* Precedence cut off */
#define NR_ICMP_UNREACH 15     /* total subcodes */

#define ICMP_SOURCE_QUENCH 4 /* Source Quench */
#define ICMP_REDIRECT 5      /* Redirect (change route) */
/* Codes for ICMP_REDIRECT. */
#define ICMP_REDIR_NET 0     /* Redirect Net */
#define ICMP_REDIR_HOST 1    /* Redirect Host */
#define ICMP_REDIR_NETTOS 2  /* Redirect Net for TOS */
#define ICMP_REDIR_HOSTTOS 3 /* Redirect Host for TOS */

#define ICMP_ECHO 8             /* Echo Request */
#define ICMP_ROUTERADV 9        /* Router Advertisement -- RFC 1256 */
#define ICMP_ROUTERDISCOVERY 10 /* Router Discovery -- RFC 1256 */
#define ICMP_TIME_EXCEEDED 11   /* Time Exceeded */
/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL 0      /* TTL count exceeded */
#define ICMP_EXC_FRAGTIME 1 /* Fragment Reass time exceeded */

#define ICMP_PARAMETERPROB 12  /* Parameter Problem */
#define ICMP_TIMESTAMP 13      /* Timestamp Request */
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply */
#define ICMP_INFO_REQUEST 15   /* Information Request */
#define ICMP_INFO_REPLY 16     /* Information Reply */
#define ICMP_ADDRESS 17        /* Address Mask Request */
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply */
#define NR_ICMP_TYPES 18

#define ICMP_MINLEN 8 /* abs minimum */

typedef unsigned short u_short;
typedef unsigned char u_char;

typedef struct icmp_header icmphdr_t;

struct icmp_header {
  u_char icmp_type;   /* type of message, see below */
  u_char icmp_code;   /* type sub code */
  u_short icmp_cksum; /* ones complement cksum of struct */
  union {
    u_char ih_pptr;           /* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr; /* ICMP_REDIRECT */
    struct ih_idseq {
      u_short icd_id;
      u_short icd_seq;
    } ih_idseq;
    int ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU discovery as per rfc 1191 */
    struct ih_pmtu {
      u_short ipm_void;
      u_short ipm_nextmtu;
    } ih_pmtu;

    /* ICMP_ROUTERADV -- RFC 1256 */
    struct ih_rtradv {
      u_char irt_num_addrs; /* Number of addresses following the msg */
      u_char irt_wpa;       /* Address Entry Size (32-bit words) */
      u_short irt_lifetime; /* Lifetime */
    } ih_rtradv;

  } icmp_hun;
#define icmp_pptr icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id icmp_hun.ih_idseq.icd_id
#define icmp_seq icmp_hun.ih_idseq.icd_seq
#define icmp_void icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime icmp_hun.ih_rtradv.irt_lifetime

  union {
    struct id_ts /* ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY */
    {
      n_time its_otime; /* Originate timestamp */
      n_time its_rtime; /* Recieve timestamp */
      n_time its_ttime; /* Transmit timestamp */
    } id_ts;
    struct id_ip /* Original IP header */
    {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    u_long id_mask; /* ICMP_ADDRESS, ICMP_ADDRESSREPLY */
    char id_data[1];
  } icmp_dun;
#define icmp_otime icmp_dun.id_ts.its_otime
#define icmp_rtime icmp_dun.id_ts.its_rtime
#define icmp_ttime icmp_dun.id_ts.its_ttime
#define icmp_ip icmp_dun.id_ip.idi_ip
#define icmp_mask icmp_dun.id_mask
#define icmp_data icmp_dun.id_data
};

typedef struct ping_data PING;
typedef int (*ping_efp)(int code, void *closure, struct sockaddr_in *dest,
                        struct sockaddr_in *from, struct ip *ip,
                        icmphdr_t *icmp, int datalen);

struct ping_data {
  int ping_fd;       /* Raw socket descriptor */
  int ping_type;     /* Type of packets to send */
  int ping_count;    /* Number of packets to send */
  int ping_interval; /* Number of seconds to wait between sending pkts */
  struct sockaddr_in ping_dest; /* whom to ping */
  char *ping_hostname;          /* Printable hostname */
  size_t ping_datalen;          /* Length of data */
  int ping_ident;               /* Our identifier */

  ping_efp ping_event; /* User-defined handler */
  void *ping_closure;  /* User-defined data */

  /* Runtime info */
  int ping_cktab_size;
  char *ping_cktab;

  u_char *ping_buffer; /* I/O buffer */
  struct sockaddr_in ping_from;
  long ping_num_xmit; /* Number of packets transmitted */
  long ping_num_recv; /* Number of packets received */
  long ping_num_rept; /* Number of duplicates received */
};

PING *ping;
unsigned long preload = 0;
size_t data_length = PING_DATALEN;
u_char *data_buffer;
unsigned options;

PING *ping_init(int type, int ident) {
  int fd;
  struct protoent *proto;
  PING *p;

  /* Initialize raw ICMP socket */
  if (!(proto = getprotobyname("icmp"))) {
    fprintf(stderr, "ping: unknown protocol icmp.\n");
    return NULL;
  }
  if ((fd = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
    if (errno == EPERM) {
      fprintf(stderr, "ping: ping must run as root\n");
    }
    return NULL;
  }

  /* Allocate PING structure and initialize it to default values */
  if (!(p = malloc(sizeof(*p)))) {
    close(fd);
    return p;
  }

  memset(p, 0, sizeof(*p));

  p->ping_fd = fd;
  p->ping_type = type;
  p->ping_count = 0;
  p->ping_interval = PING_INTERVAL;
  p->ping_datalen = sizeof(icmphdr_t);
  /* Make sure we use only 16 bits in this field, id for icmp is a u_short.  */
  p->ping_ident = ident & 0xFFFF;
  p->ping_cktab_size = PING_CKTABSIZE;
  return p;
}

void ping_set_sockopt(PING *ping, int opt, void *val, int valsize) {
  setsockopt(ping->ping_fd, SOL_SOCKET, opt, (char *)&val, valsize);
}

void ping_set_type(PING *p, int type) { p->ping_type = type; }

void ping_set_event_handler(PING *ping, ping_efp pf, void *closure) {
  ping->ping_event = pf;
  ping->ping_closure = closure;
}

void ping_set_packetsize(PING *ping, int size) { ping->ping_datalen = size; }

void ping_set_count(PING *ping, int count) { ping->ping_count = count; }

int ping_set_dest(PING *ping, char *host) {
  struct sockaddr_in *s_in = &ping->ping_dest;
  s_in->sin_family = AF_INET;
  if (inet_aton(host, &s_in->sin_addr)) {
    ping->ping_hostname = strdup(host);
  } else {
    struct hostent *hp = gethostbyname(host);
    if (!hp)
      return 1;

    s_in->sin_family = hp->h_addrtype;
    if (hp->h_length > (int)sizeof(s_in->sin_addr))
      hp->h_length = sizeof(s_in->sin_addr);

    memcpy(&s_in->sin_addr, hp->h_addr, hp->h_length);
    ping->ping_hostname = strdup(hp->h_name);
  }
  return 0;
}

void print_address(int dupflag, void *closure, struct sockaddr_in *dest,
                   struct sockaddr_in *from, struct ip *ip, icmphdr_t *icmp,
                   int datalen) {
  struct in_addr addr;

  printf("%d bytes from %s: icmp_seq=%u", datalen,
         inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr), icmp->icmp_seq);
  if (dupflag)
    printf(" (DUP!)");
  addr.s_addr = icmp->icmp_mask;
  printf("icmp_mask = %s", inet_ntoa(addr));
  printf("\n");
  return;
}

int recv_address(int code, void *closure, struct sockaddr_in *dest,
                 struct sockaddr_in *from, struct ip *ip, icmphdr_t *icmp,
                 int datalen) {
  switch (code) {
  case PEV_RESPONSE:
  case PEV_DUPLICATE:
    print_address(code == PEV_DUPLICATE, closure, dest, from, ip, icmp,
                  datalen);
    break;
    /* case PEV_NOECHO:; */
    /*   print_icmp_header (from, ip, icmp, datalen); */
  }
  return 0;
}

int address_finish() { return 0; }

int volatile stop = 0;

void sig_int(int signal) { stop = 1; }

int _ping_setbuf(PING *p) {
  if (!p->ping_buffer) {
    p->ping_buffer = malloc(_PING_BUFLEN(p));
    if (!p->ping_buffer)
      return -1;
  }
  if (!p->ping_cktab) {
    p->ping_cktab = malloc(p->ping_cktab_size);
    if (!p->ping_cktab)
      return -1;
    memset(p->ping_cktab, 0, p->ping_cktab_size);
  }
  return 0;
}

int ping_set_data(PING *p, void *data, size_t off, size_t len) {
  icmphdr_t *icmp;

  if (_ping_setbuf(p))
    return -1;
  if (p->ping_datalen < off + len)
    return -1;
  icmp = (icmphdr_t *)p->ping_buffer;
  memcpy(icmp->icmp_data + off, data, len);
  return 0;
}

size_t _ping_packetsize(PING *p) {
  switch (p->ping_type) {
  case ICMP_TIMESTAMP:
  case ICMP_TIMESTAMPREPLY:
    return 20;

  default:
    return 8 + p->ping_datalen;
  }
  return 8; /* to keep compiler happy */
}

u_short icmp_cksum(u_char *addr, int len) {
  register int sum = 0;
  u_short answer = 0;
  u_short *wp;

  for (wp = (u_short *)addr; len > 1; wp++, len -= 2)
    sum += *wp;

  /* Take in an odd byte if present */
  if (len == 1) {
    *(u_char *)&answer = *(u_char *)wp;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff); /* add high 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return answer;
}

int icmp_generic_encode(u_char *buffer, size_t bufsize, int type, int ident,
                        int seqno) {
  icmphdr_t *icmp;

  if (bufsize < 8)
    return -1;
  icmp = (icmphdr_t *)buffer;
  icmp->icmp_type = type;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_seq = seqno;
  icmp->icmp_id = ident;

  icmp->icmp_cksum = icmp_cksum(buffer, bufsize);
  return 0;
}

int icmp_echo_encode(u_char *buffer, size_t bufsize, int ident, int seqno) {
  return icmp_generic_encode(buffer, bufsize, ICMP_ECHO, ident, seqno);
}

int icmp_timestamp_encode(u_char *buffer, size_t bufsize, int ident,
                          int seqno) {
  icmphdr_t *icmp;
  struct timeval tv;
  unsigned long v;

  if (bufsize < 20)
    return -1;

  gettimeofday(&tv, NULL);
  v = htonl((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);

  icmp = (icmphdr_t *)buffer;
  icmp->icmp_otime = v;
  icmp->icmp_rtime = v;
  icmp->icmp_ttime = v;
  icmp_generic_encode(buffer, bufsize, ICMP_TIMESTAMP, ident, seqno);
  return 0;
}

int icmp_address_encode(u_char *buffer, size_t bufsize, int ident, int seqno) {
  icmphdr_t *icmp;

  if (bufsize < 12)
    return -1;

  icmp = (icmphdr_t *)buffer;
  icmp->icmp_mask = 0;
  icmp_generic_encode(buffer, bufsize, ICMP_ADDRESS, ident, seqno);
  return 0;
}

int ping_xmit(PING *p) {
  int i, buflen;

  if (_ping_setbuf(p))
    return -1;

  buflen = _ping_packetsize(p);

  /* Mark sequence number as sent */
  _PING_CLR(p, p->ping_num_xmit % p->ping_cktab_size);

  /* Encode ICMP header */
  switch (p->ping_type) {
  case ICMP_ECHO:
    icmp_echo_encode(p->ping_buffer, buflen, p->ping_ident, p->ping_num_xmit);
    break;
  case ICMP_TIMESTAMP:
    icmp_timestamp_encode(p->ping_buffer, buflen, p->ping_ident,
                          p->ping_num_xmit);
    break;
  case ICMP_ADDRESS:
    icmp_address_encode(p->ping_buffer, buflen, p->ping_ident,
                        p->ping_num_xmit);
    break;
  default:
    icmp_generic_encode(p->ping_buffer, buflen, p->ping_type, p->ping_ident,
                        p->ping_num_xmit);
    break;
  }

  i = sendto(p->ping_fd, (char *)p->ping_buffer, buflen, 0,
             (struct sockaddr *)&p->ping_dest, sizeof(struct sockaddr_in));
  if (i < 0) {
    perror("ping: sendto");
  } else {
    p->ping_num_xmit++;
    if (i != buflen)
      printf("ping: wrote %s %d chars, ret=%d\n", p->ping_hostname, buflen, i);
  }

  return 0;
}

int send_echo(PING *ping) {
  int off = 0;

  if (PING_TIMING(data_length)) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ping_set_data(ping, &tv, 0, sizeof(tv));
    off += sizeof(tv);
  }
  if (data_buffer)
    ping_set_data(ping, data_buffer, off,
                  data_length > PING_HEADER_LEN ? data_length - PING_HEADER_LEN
                                                : data_length);
  return ping_xmit(ping);
}

int icmp_generic_decode(u_char *buffer, size_t bufsize, struct ip **ipp,
                        icmphdr_t **icmpp) {
  size_t hlen;
  u_short cksum;
  struct ip *ip;
  icmphdr_t *icmp;

  /* IP header */
  ip = (struct ip *)buffer;
  hlen = ip->ip_hl << 2;
  if (bufsize < hlen + ICMP_MINLEN)
    return -1;

  /* ICMP header */
  icmp = (icmphdr_t *)(buffer + hlen);

  /* Prepare return values */
  *ipp = ip;
  *icmpp = icmp;

  /* Recompute checksum */
  cksum = icmp->icmp_cksum;
  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = icmp_cksum((u_char *)icmp, bufsize - hlen);
  if (icmp->icmp_cksum != cksum)
    return 1;
  return 0;
}

int ping_recv(PING *p) {
  int fromlen = sizeof(p->ping_from);
  int n, rc;
  icmphdr_t *icmp;
  struct ip *ip;
  int dupflag;

  if ((n = recvfrom(p->ping_fd, (char *)p->ping_buffer, _PING_BUFLEN(p), 0,
                    (struct sockaddr *)&p->ping_from, &fromlen)) < 0)
    return -1;

  if ((rc = icmp_generic_decode(p->ping_buffer, n, &ip, &icmp)) < 0) {
    /*FIXME: conditional */
    fprintf(stderr, "packet too short (%d bytes) from %s\n", n,
            inet_ntoa(p->ping_from.sin_addr));
    return -1;
  }

  switch (icmp->icmp_type) {
  case ICMP_ECHOREPLY:
  case ICMP_TIMESTAMPREPLY:
  case ICMP_ADDRESSREPLY:
    /*    case ICMP_ROUTERADV: */
    if (icmp->icmp_id != p->ping_ident)
      return -1;
    if (rc) {
      fprintf(stderr, "checksum mismatch from %s\n",
              inet_ntoa(p->ping_from.sin_addr));
    }

    p->ping_num_recv++;
    if (_PING_TST(p, icmp->icmp_seq % p->ping_cktab_size)) {
      p->ping_num_rept++;
      p->ping_num_recv--;
      dupflag = 1;
    } else {
      _PING_SET(p, icmp->icmp_seq % p->ping_cktab_size);
      dupflag = 0;
    }

    if (p->ping_event)
      (*p->ping_event)(dupflag ? PEV_DUPLICATE : PEV_RESPONSE, p->ping_closure,
                       &p->ping_dest, &p->ping_from, ip, icmp, n);
    break;

  default:
    if (p->ping_event)
      (*p->ping_event)(PEV_NOECHO, p->ping_closure, &p->ping_dest,
                       &p->ping_from, ip, icmp, n);
  }
  return 0;
}

int ping_run(PING *ping, int (*finish)()) {
  fd_set fdset;
  int fdmax;
  struct timeval timeout;
  struct timeval last, intvl, now;
  struct timeval *t = NULL;
  int finishing = 0;

  signal(SIGINT, sig_int);

  fdmax = ping->ping_fd + 1;

  while (preload--)
    send_echo(ping);

  if (options & OPT_FLOOD) {
    intvl.tv_sec = 0;
    intvl.tv_usec = 10000;
  } else {
    intvl.tv_sec = ping->ping_interval;
    intvl.tv_usec = 0;
  }

  gettimeofday(&last, NULL);
  send_echo(ping);

  while (!stop) {
    int n, len;

    FD_ZERO(&fdset);
    FD_SET(ping->ping_fd, &fdset);
    gettimeofday(&now, NULL);
    timeout.tv_sec = last.tv_sec + intvl.tv_sec - now.tv_sec;
    timeout.tv_usec = last.tv_usec + intvl.tv_usec - now.tv_usec;

    while (timeout.tv_usec < 0) {
      timeout.tv_usec += 1000000;
      timeout.tv_sec--;
    }
    while (timeout.tv_usec >= 1000000) {
      timeout.tv_usec -= 1000000;
      timeout.tv_sec++;
    }

    if (timeout.tv_sec < 0)
      timeout.tv_sec = timeout.tv_usec = 0;

    if ((n = select(fdmax, &fdset, NULL, NULL, &timeout)) < 0) {
      if (errno != EINTR)
        perror("ping: select");
      continue;
    } else if (n == 1) {
      len = ping_recv(ping);
      if (t == 0) {
        gettimeofday(&now, NULL);
        t = &now;
      }
      if (ping->ping_count && ping->ping_num_recv >= ping->ping_count)
        break;
    } else {
      if (!ping->ping_count || ping->ping_num_recv < ping->ping_count) {
        send_echo(ping);
        if (!(options & OPT_QUIET) && options & OPT_FLOOD) {
          putchar('.');
        }
      } else if (finishing)
        break;
      else {
        finishing = 1;

        intvl.tv_sec = MAXWAIT;
      }
      gettimeofday(&last, NULL);
    }
  }
  if (finish)
    return (*finish)();
  return 0;
}

int ping_address(int argc, char **argv) {
  ping_set_type(ping, ICMP_ADDRESS);
  ping_set_event_handler(ping, recv_address, NULL);
  ping_set_packetsize(ping, 12); /* FIXME: constant */
  ping_set_count(ping, 1);

  argv++;

  if (ping_set_dest(ping, *argv)) {
    fprintf(stderr, "ping: unknown host\n");
    exit(1);
  }

  printf("PING %s (%s): sending address mask request\n", ping->ping_hostname,
         inet_ntoa(ping->ping_dest.sin_addr));

  return ping_run(ping, address_finish);
}

void init_data_buffer(u_char *pat, int len) {
  int i = 0;
  u_char *p;

  if (data_length == 0)
    return;
  data_buffer = malloc(data_length);
  if (!data_buffer) {
    fprintf(stderr, "ping: out of memory\n");
    exit(1);
  }
  if (pat) {
    for (p = data_buffer; p < data_buffer + data_length; p++) {
      *p = pat[i];
      if (i++ >= len)
        i = 0;
    }
  } else {
    for (i = 0; i < data_length; i++)
      data_buffer[i] = i;
  }
}

#define NROUTES 9

struct ping_stat {
  double tmin;   /* minimum round trip time */
  double tmax;   /* maximum round trip time */
  double tsum;   /* sum of all times, for doing average */
  double tsumsq; /* sum of all times squared, for std. dev. */
};

static void tvsub(out, in) register struct timeval *out, *in;
{
  if ((out->tv_usec -= in->tv_usec) < 0) {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

int print_echo(int dupflag, struct ping_stat *ping_stat,
               struct sockaddr_in *dest, struct sockaddr_in *from,
               struct ip *ip, icmphdr_t *icmp, int datalen) {
  int hlen;
  struct timeval tv;
  int timing = 0;
  double triptime = 0.0;

  gettimeofday(&tv, NULL);

  /* Length of IP header */
  hlen = ip->ip_hl << 2;

  /* Length of ICMP header+payload */
  datalen -= hlen;

  /* Do timing */
  if (PING_TIMING(datalen - 8)) {
    struct timeval tv1, *tp;

    timing++;
    tp = (struct timeval *)icmp->icmp_data;

    /* Avoid unaligned data: */
    memcpy(&tv1, tp, sizeof(tv1));
    tvsub(&tv, &tv1);

    triptime = ((double)tv.tv_sec) * 1000.0 + ((double)tv.tv_usec) / 1000.0;
    ping_stat->tsum += triptime;
    ping_stat->tsumsq += triptime * triptime;
    if (triptime < ping_stat->tmin)
      ping_stat->tmin = triptime;
    if (triptime > ping_stat->tmax)
      ping_stat->tmax = triptime;
  }

  if (options & OPT_QUIET)
    return 0;
  if (options & OPT_FLOOD) {
    putchar('\b');
    return 0;
  }

  printf("%d bytes from %s: icmp_seq=%u", datalen,
         inet_ntoa(*(struct in_addr *)&from->sin_addr.s_addr), icmp->icmp_seq);
  printf(" ttl=%d", ip->ip_ttl);
  if (timing)
    printf(" time=%.3f ms", triptime);
  if (dupflag)
    printf(" (DUP!)");

  // print_ip_opt (ip, hlen);
  printf("\n");

  return 0;
}

int handler(int code, void *closure, struct sockaddr_in *dest,
            struct sockaddr_in *from, struct ip *ip, icmphdr_t *icmp,
            int datalen) {
  switch (code) {
  case PEV_RESPONSE:
  case PEV_DUPLICATE:
    print_echo(code == PEV_DUPLICATE, (struct ping_stat *)closure, dest, from,
               ip, icmp, datalen);
    break;
    /* case PEV_NOECHO:; */
    /*   print_icmp_header(from, ip, icmp, datalen); */
  }
  return 0;
}

int ping_finish() {
  fflush(stdout);
  printf("--- %s ping statistics ---\n", ping->ping_hostname);
  printf("%ld packets transmitted, ", ping->ping_num_xmit);
  printf("%ld packets received, ", ping->ping_num_recv);
  if (ping->ping_num_rept)
    printf("+%ld duplicates, ", ping->ping_num_rept);
  if (ping->ping_num_xmit) {
    if (ping->ping_num_recv > ping->ping_num_xmit)
      printf("-- somebody's printing up packets!");
    else
      printf("%d%% packet loss",
             (int)(((ping->ping_num_xmit - ping->ping_num_recv) * 100) /
                   ping->ping_num_xmit));
  }
  printf("\n");
  return 0;
}

int echo_finish() {
  ping_finish();
  if (ping->ping_num_recv && PING_TIMING(data_length)) {
    struct ping_stat *ping_stat = (struct ping_stat *)ping->ping_closure;
    double total = ping->ping_num_recv + ping->ping_num_rept;
    double avg = ping_stat->tsum / total;
    double vari = ping_stat->tsumsq / total - avg * avg;

    printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
           ping_stat->tmin, avg, ping_stat->tmax, sqrt(vari));
  }
  exit(ping->ping_num_recv == 0);
}

int ping_echo(int argc, char **argv) {
  argv++;
#ifdef IP_OPTIONS
  char rspace[3 + 4 * NROUTES + 1]; /* record route space */
#endif
  struct ping_stat ping_stat;

  if (options & OPT_FLOOD && options & OPT_INTERVAL) {
    fprintf(stderr, "ping: -f and -i incompatible options.\n");
    return 2;
  }

  memset(&ping_stat, 0, sizeof(ping_stat));
  ping_stat.tmin = 999999999.0;

  ping_set_type(ping, ICMP_ECHO);
  ping_set_packetsize(ping, data_length);
  ping_set_event_handler(ping, handler, &ping_stat);

  if (ping_set_dest(ping, *argv)) {
    fprintf(stderr, "ping: unknown host\n");
    exit(1);
  }

  if (options & OPT_RROUTE) {
#ifdef IP_OPTIONS
    memset(rspace, 0, sizeof(rspace));
    rspace[IPOPT_OPTVAL] = IPOPT_RR;
    rspace[IPOPT_OLEN] = sizeof(rspace) - 1;
    rspace[IPOPT_OFFSET] = IPOPT_MINOFF;
    if (setsockopt(ping->ping_fd, IPPROTO_IP, IP_OPTIONS, rspace,
                   sizeof(rspace)) < 0) {
      perror("ping: record route");
      exit(2);
    }
#else
    fprintf(stderr,
            "ping: record route not available in this implementation.\n");
    exit(2);
#endif /* IP_OPTIONS */
  }

  printf("PING %s (%s): %d data bytes\n", ping->ping_hostname,
         inet_ntoa(ping->ping_dest.sin_addr), data_length);

  return ping_run(ping, echo_finish);
}

int main(int argc, char *argv[]) {
  int one = 1;
  int pattern_len = 16;
  u_char *patptr = NULL;

  init_data_buffer(patptr, pattern_len);

  ping = ping_init(ICMP_ECHO, getpid());
  if (ping == NULL) {
    fprintf(stderr, "can't init ping: %s\n", strerror(errno));
    exit(1);
  }
  ping_set_sockopt(ping, SO_BROADCAST, (char *)&one, sizeof(one));

  setuid(getuid());

  ping_echo(argc, argv);
  return 0;
}
