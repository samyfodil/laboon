// A run without networking has loopback only, as Linux does with no network:
// TCP and UDP on 127.0.0.1 and ::1 work, with Linux's names, ports and errors,
// and an outside address (192.0.2.1, a documentation address no network
// routes) is unreachable over TCP and UDP. With no network at all (laboon
// -no-net) there is no INET socket.
// Usage: loopnet.elf loopback | local [port [dns]] | none
// (local is loopback without the outside address, for a host with a network
// whose loopback is the run's own; with a port, a host service listening on
// 127.0.0.1 there must be out of reach)
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

// roundtrip listens on addr, connects to it, and checks a message crosses.
static void roundtrip(int family, const char *addr) {
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof ss);
	socklen_t len;
	if (family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)&ss;
		a->sin_family = AF_INET;
		inet_pton(AF_INET, addr, &a->sin_addr);
		len = sizeof *a;
	} else {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
		a->sin6_family = AF_INET6;
		inet_pton(AF_INET6, addr, &a->sin6_addr);
		len = sizeof *a;
	}
	int l = socket(family, SOCK_STREAM, 0);
	CHECK(l >= 0, "socket(%s): %s", addr, strerror(errno));
	if (l < 0)
		return;
	CHECK(bind(l, (struct sockaddr *)&ss, len) == 0, "bind %s: %s", addr, strerror(errno));
	CHECK(listen(l, 1) == 0, "listen %s: %s", addr, strerror(errno));
	getsockname(l, (struct sockaddr *)&ss, &len);
	int c = socket(family, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&ss, len) == 0, "connect %s: %s", addr, strerror(errno));
	int a = accept(l, 0, 0);
	CHECK(a >= 0, "accept %s: %s", addr, strerror(errno));
	char b[8] = "";
	CHECK(write(c, "ping", 4) == 4 && read(a, b, sizeof b) == 4 && memcmp(b, "ping", 4) == 0, "nothing crossed %s", addr);
	close(a);
	close(c);
	close(l);
}

// unreachable checks that a connect to an outside address fails with
// ENETUNREACH.
static void unreachable(int type) {
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(type == SOCK_STREAM ? 80 : 53)};
	inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
	int s = socket(AF_INET, type, 0);
	int r = connect(s, (struct sockaddr *)&a, sizeof a);
	CHECK(r == -1 && errno == ENETUNREACH, "%s connect to 192.0.2.1: %d %s", type == SOCK_STREAM ? "TCP" : "UDP", r, strerror(errno));
	close(s);
}

static struct sockaddr_in in4(const char *ip, int port) {
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	inet_pton(AF_INET, ip, &a.sin_addr);
	return a;
}

static int portOf(int s) {
	struct sockaddr_storage ss;
	socklen_t len = sizeof ss;
	getsockname(s, (struct sockaddr *)&ss, &len);
	return ss.ss_family == AF_INET ? ntohs(((struct sockaddr_in *)&ss)->sin_port) : ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
}

// udp sends a datagram between two sockets on 127.0.0.1: the sender is bound
// on its first send, and the receiver sees its address.
static void udp(void) {
	int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in at = in4("127.0.0.1", 0);
	CHECK(bind(a, (struct sockaddr *)&at, sizeof at) == 0, "udp bind: %s", strerror(errno));
	at.sin_port = htons(portOf(a));
	CHECK(sendto(b, "dgram", 5, 0, (struct sockaddr *)&at, sizeof at) == 5, "sendto: %s", strerror(errno));
	char buf[16];
	struct sockaddr_in from;
	socklen_t fl = sizeof from;
	ssize_t n = recvfrom(a, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
	char ip[32] = "";
	inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
	CHECK(n == 5 && memcmp(buf, "dgram", 5) == 0, "recvfrom %zd: %s", n, strerror(errno));
	CHECK(portOf(b) >= 32768 && ntohs(from.sin_port) == portOf(b) && strcmp(ip, "127.0.0.1") == 0,
		"from %s:%d, the sender is on %d", ip, ntohs(from.sin_port), portOf(b));
	// Datagrams sent before any is read each arrive as sent.
	CHECK(sendto(b, "first", 5, 0, (struct sockaddr *)&at, sizeof at) == 5, "sendto first: %s", strerror(errno));
	CHECK(sendto(b, "again", 5, 0, (struct sockaddr *)&at, sizeof at) == 5, "sendto again: %s", strerror(errno));
	n = recv(a, buf, sizeof buf, 0);
	CHECK(n == 5 && memcmp(buf, "first", 5) == 0, "first datagram: %zd %.*s", n, (int)(n > 0 ? n : 0), buf);
	n = recv(a, buf, sizeof buf, 0);
	CHECK(n == 5 && memcmp(buf, "again", 5) == 0, "second datagram: %zd %.*s", n, (int)(n > 0 ? n : 0), buf);
	close(a);
	close(b);
}

// dnsq builds a query for label.invalid.
static int dnsq(unsigned char *q, int id, const char *label, int type) {
	int n = 0, l = strlen(label);
	unsigned char hdr[12] = {id >> 8, id & 0xff, 1, 0, 0, 1};
	memcpy(q, hdr, 12);
	n = 12;
	q[n++] = l;
	memcpy(q + n, label, l);
	n += l;
	q[n++] = 7;
	memcpy(q + n, "invalid", 7);
	n += 7;
	q[n++] = 0;
	q[n++] = 0;
	q[n++] = type;
	q[n++] = 0;
	q[n++] = 1;
	return n;
}

// dnspair sends two queries of one length before reading, as a resolver asks
// for A and AAAA at once: each gets its own reply. The names are outside the allowlist, so
// they are refused without a lookup.
static void dnspair(void) {
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in ns = in4("192.0.2.53", 53);
	unsigned char q[64], r[512];
	int n = dnsq(q, 0x1111, "first", 1);
	CHECK(sendto(s, q, n, 0, (struct sockaddr *)&ns, sizeof ns) == n, "query first: %s", strerror(errno));
	n = dnsq(q, 0x2222, "again", 28);
	CHECK(sendto(s, q, n, 0, (struct sockaddr *)&ns, sizeof ns) == n, "query second: %s", strerror(errno));
	int seen = 0;
	for (int i = 0; i < 2; i++) {
		struct pollfd p = {.fd = s, .events = POLLIN};
		CHECK(poll(&p, 1, 10000) == 1, "reply %d never came", i);
		ssize_t m = recv(s, r, sizeof r, MSG_DONTWAIT);
		if (m <= 13) {
			CHECK(0, "reply %d: %zd %s", i, m, strerror(errno));
			break;
		}
		int id = r[0] << 8 | r[1];
		const char *want = id == 0x1111 ? "first" : "again";
		CHECK((id == 0x1111 || id == 0x2222) && r[12] == strlen(want) && memcmp(r + 13, want, strlen(want)) == 0,
			"reply %d: id %#x for %.*s", i, id, r[12], r + 13);
		seen |= id == 0x1111 ? 1 : id == 0x2222 ? 2 : 0;
	}
	CHECK(seen == 3, "replies to %d of the queries (bits)", seen);
	close(s);
}

// errors checks the address errors: a port in use, also under a wildcard; an
// address no interface has; and a connect no one listens for.
static void errors(void) {
	int a = socket(AF_INET, SOCK_STREAM, 0), b = socket(AF_INET, SOCK_STREAM, 0), w = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in at = in4("127.0.0.1", 0);
	CHECK(bind(a, (struct sockaddr *)&at, sizeof at) == 0, "bind: %s", strerror(errno));
	at.sin_port = htons(portOf(a));
	CHECK(bind(b, (struct sockaddr *)&at, sizeof at) == -1 && errno == EADDRINUSE, "a second bind: %s", strerror(errno));
	struct sockaddr_in any = in4("0.0.0.0", portOf(a));
	CHECK(bind(w, (struct sockaddr *)&any, sizeof any) == -1 && errno == EADDRINUSE, "a wildcard bind over it: %s", strerror(errno));
	int o = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in other = in4("192.0.2.1", 0);
	CHECK(bind(o, (struct sockaddr *)&other, sizeof other) == -1 && errno == EADDRNOTAVAIL, "bind 192.0.2.1: %s", strerror(errno));
	int c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&at, sizeof at) == -1 && errno == ECONNREFUSED, "connect to a bound, not listening port: %s", strerror(errno));
	close(a);
	close(b);
	close(w);
	close(o);
	close(c);
}

// dual has an IPv6 wildcard listener take an IPv4 connection, whose peer it
// sees v4-mapped, and checks each end's names.
static void dual(void) {
	int l = socket(AF_INET6, SOCK_STREAM, 0);
	struct sockaddr_in6 any = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT};
	CHECK(bind(l, (struct sockaddr *)&any, sizeof any) == 0 && listen(l, 1) == 0, "v6 listen: %s", strerror(errno));
	struct sockaddr_in to = in4("127.0.0.1", portOf(l));
	int c = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&to, sizeof to) == 0, "v4 connect to the v6 wildcard: %s", strerror(errno));
	struct sockaddr_in6 peer;
	socklen_t pl = sizeof peer;
	int a = accept(l, (struct sockaddr *)&peer, &pl);
	char ip[64] = "";
	inet_ntop(AF_INET6, &peer.sin6_addr, ip, sizeof ip);
	CHECK(a >= 0 && peer.sin6_family == AF_INET6 && strcmp(ip, "::ffff:127.0.0.1") == 0 && ntohs(peer.sin6_port) == portOf(c),
		"accepted peer %s:%d, the client is on %d", ip, ntohs(peer.sin6_port), portOf(c));
	struct sockaddr_in cp;
	socklen_t cl = sizeof cp;
	CHECK(getpeername(c, (struct sockaddr *)&cp, &cl) == 0 && ntohs(cp.sin_port) == portOf(l), "client peer port %d", ntohs(cp.sin_port));
	CHECK(portOf(a) == portOf(l), "accepted socket on port %d, the listener on %d", portOf(a), portOf(l));
	close(a);
	close(c);
	close(l);
}

int main(int argc, char **argv) {
	if (argc > 1 && strcmp(argv[1], "none") == 0) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		CHECK(s == -1 && errno == EAFNOSUPPORT, "socket(AF_INET) with no network: %d %s", s, strerror(errno));
		s = socket(AF_INET6, SOCK_DGRAM, 0);
		CHECK(s == -1 && errno == EAFNOSUPPORT, "socket(AF_INET6) with no network: %d %s", s, strerror(errno));
	} else {
		roundtrip(AF_INET, "127.0.0.1");
		roundtrip(AF_INET6, "::1");
		roundtrip(AF_INET, "0.0.0.0");
		udp();
		errors();
		dual();
		if (argc < 2 || strcmp(argv[1], "local") != 0) {
			unreachable(SOCK_STREAM);
			unreachable(SOCK_DGRAM);
		}
		if (argc > 2) {
			struct sockaddr_in host = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
			inet_pton(AF_INET, "127.0.0.1", &host.sin_addr);
			int c = socket(AF_INET, SOCK_STREAM, 0);
			int r = connect(c, (struct sockaddr *)&host, sizeof host);
			CHECK(r == -1 && errno == ECONNREFUSED, "connect to the host's 127.0.0.1:%s: %d %s", argv[2], r, strerror(errno));
			close(c);
		}
		if (argc > 3 && strcmp(argv[3], "dns") == 0)
			dnspair();
	}
	printf("loopnet fails=%d\n", fails);
	return fails != 0;
}
