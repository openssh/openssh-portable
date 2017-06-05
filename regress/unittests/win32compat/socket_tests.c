/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*/

#include "includes.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include "../test_helper/test_helper.h"
#include "tests.h"

#define PORT "34912"  
#define BACKLOG 2  
#define SMALL_RECV_BUF_SIZE 128

#pragma warning(disable:4267)

int listen_fd, accept_fd, connect_fd, retValue;
struct addrinfo hints, *servinfo;
fd_set read_set, write_set, except_set;
struct timeval time_val;
struct sockaddr_storage their_addr;
int their_addr_len = sizeof(their_addr);
char *send_buf, *recv_buf;

int
unset_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		return (-1);

	if (!(val & O_NONBLOCK))
		return (0);
	
	val &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		return (-1);
	
	return (0);
}

int
set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		return (-1);

	if (val & O_NONBLOCK)
		return (0);
	
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		return (-1);
	
	return (0);
}

void 
prep_input_buffer(char* buf, int size, int seed)
{
	int ctr = 1;
	int *cur = (int*)buf;
	for (; size; size -= 4) {
		*(cur++) = ctr;
		ctr += seed;
	}
}

void 
socket_fd_tests()
{
	fd_set set, *pset;
	pset = &set;

	{
		TEST_START("fd_set initial state");
		
		FD_ZERO(pset);
		ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(1, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
		
		TEST_DONE();
	}

	{
		TEST_START("FD_SET");

		FD_SET(0, pset);
		FD_SET(1, pset);
		ASSERT_CHAR_EQ(1, FD_ISSET(0, pset));
		ASSERT_CHAR_EQ(1, FD_ISSET(1, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));

		TEST_DONE();
	}

	{
		TEST_START("FD_CLR");
		
		FD_CLR(0, pset);
		ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
		ASSERT_CHAR_EQ(1, FD_ISSET(1, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));

		TEST_DONE();
	}

	{
		TEST_START("FD_ZERO");
		
		FD_ZERO(pset);
		ASSERT_CHAR_EQ(0, FD_ISSET(0, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(1, pset));
		ASSERT_CHAR_EQ(0, FD_ISSET(2, pset));
		
		TEST_DONE();
	}

	{
		TEST_START("BAD FDs");
		
		ASSERT_INT_EQ(accept(-1, NULL, NULL), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(setsockopt(MAX_FDS, 0, 0, NULL, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		/*0,1,2 fd's are initialized */
		ASSERT_INT_EQ(getsockopt(3, 0, 0, NULL, NULL), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(getsockname(4, NULL, NULL), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(getpeername(5, NULL, NULL), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(listen(6, 2), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(bind(7, NULL, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(connect(8, NULL, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(recv(9, NULL, 0, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(send(10, NULL, 0, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(shutdown(11, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(read(MAX_FDS + 1, NULL, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(write(INFINITE, NULL, 0), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(fstat(11, NULL), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(isatty(12), 0);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_PTR_EQ(fdopen(13, NULL), NULL);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(close(14), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(fcntl(15, 1), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(dup(16), -1);
		ASSERT_INT_EQ(errno, EBADF);
		ASSERT_INT_EQ(dup2(17, 18), -1);
		ASSERT_INT_EQ(errno, EBADF);
		FD_ZERO(&read_set);
		FD_SET(20, &read_set);
		ASSERT_INT_EQ(select(21, &read_set, NULL, NULL, &time_val), -1);
		ASSERT_INT_EQ(errno, EBADF);
		FD_ZERO(&write_set);
		FD_SET(21, &write_set);
		ASSERT_INT_EQ(select(22, NULL, &write_set, NULL, &time_val), -1);
		ASSERT_INT_EQ(errno, EBADF);
		
		TEST_DONE();
	}

	{
		TEST_START("socket failures");
		
		ASSERT_INT_EQ(setsockopt(0, 0, SO_RCVTIMEO, NULL, 0), -1);
		ASSERT_INT_EQ(errno, ENOTSOCK);
		connect_fd = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);
		ASSERT_INT_NE(connect_fd, -1);
		ASSERT_INT_EQ(setsockopt(connect_fd, 0, SO_RCVTIMEO, NULL, 0), -1);
		ASSERT_INT_EQ(errno, ENOTSUP);
		close(connect_fd);
		
		TEST_DONE();
	}

	{
		TEST_START("min fd allocation");
		
		connect_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_INT_EQ(connect_fd, 3);
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_INT_EQ(listen_fd, 4);
		close(connect_fd);
		connect_fd = socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_INT_EQ(connect_fd, 3); /*minimum free fd gets allocated*/
		close(connect_fd);
		close(listen_fd);
		
		TEST_DONE();
	}
}

void 
socket_blocking_io_tests()
{
	char* small_send_buf = "sample payload";
	char small_recv_buf[SMALL_RECV_BUF_SIZE];

	{
		TEST_START("Basic IPv4 client server connection setup");
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		retValue = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo);
		ASSERT_INT_EQ(retValue, 0);
		listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(listen_fd, -1);
		retValue = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		retValue = listen(listen_fd, BACKLOG);
		ASSERT_INT_EQ(retValue, 0);
		//call listen again??
		connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(connect_fd, -1);
		retValue = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		//call connect again??
		their_addr_len = sizeof(their_addr);
		accept_fd = accept(listen_fd, (struct sockaddr*)&their_addr, &their_addr_len);
		ASSERT_INT_NE(accept_fd, -1);
		retValue = close(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		//call accept after listen_fd is closed??
		
		TEST_DONE();
	}

	{
		TEST_START("send failures");
		
		retValue = send(accept_fd, NULL, 4, 0);/*invalid buffer*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EINVAL);
		retValue = send(accept_fd, small_send_buf, 0, 0); /*invalid buffer*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EINVAL);
		retValue = send(accept_fd, small_send_buf, strlen(small_send_buf), 4); /*flags not supported yet*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, ENOTSUP);
		
		TEST_DONE();
	}

	{
		TEST_START("basic send s->c");

		retValue = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));

		TEST_DONE();
	}

	{
		TEST_START("recv failures");

		retValue = recv(connect_fd, NULL, SMALL_RECV_BUF_SIZE, 0); /* invalid buffer*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EINVAL);
		retValue = recv(connect_fd, small_recv_buf, 0, 0); /*invalid buffer*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EINVAL);
		retValue = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 6); /*flags not supported yet*/
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, ENOTSUP);

		TEST_DONE();
	}

	{
		TEST_START("basic recv s->c");

		retValue = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		small_recv_buf[retValue] = '\0';
		ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
		memset(small_recv_buf, 0, sizeof(small_recv_buf));
		
		TEST_DONE();
	}

	{
		TEST_START("basic send recv c->s");

		retValue = send(connect_fd, small_send_buf, strlen(small_send_buf), 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		retValue = recv(accept_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		small_recv_buf[retValue] = '\0';
		ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
		memset(small_recv_buf, 0, sizeof(small_recv_buf));
		
		TEST_DONE();
	}

	{
		TEST_START("shutdown SD_SEND");

		retValue = shutdown(connect_fd, SD_SEND);
		ASSERT_INT_EQ(retValue, 0);
		retValue = recv(accept_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0); /* send on other side is shutdown*/
		ASSERT_INT_EQ(retValue, 0);
		retValue = shutdown(accept_fd, SD_SEND);
		ASSERT_INT_EQ(retValue, 0);
		retValue = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0); /* send on other side is shutdown*/
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	{
		TEST_START("shutdown SD_RECEIVE");

		retValue = shutdown(connect_fd, SD_RECEIVE);
		ASSERT_INT_EQ(retValue, 0);
		retValue = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, ECONNRESET);
		retValue = shutdown(accept_fd, SD_RECEIVE);
		ASSERT_INT_EQ(retValue, 0);
		retValue = send(connect_fd, small_send_buf, strlen(small_send_buf), 0);
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, ECONNRESET);
		
		TEST_DONE();
	}

	{
		TEST_START("basic close");

		retValue = close(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = close(accept_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	freeaddrinfo(servinfo);
}

void 
socket_nonblocking_io_tests()
{
	char* small_send_buf = "sample payload";
	char small_recv_buf[SMALL_RECV_BUF_SIZE];

	{
		TEST_START("IPv6 sockets setup");
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		retValue = getaddrinfo("::1", PORT, &hints, &servinfo);
		ASSERT_INT_EQ(retValue, 0);
		listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(listen_fd, -1);
		retValue = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		retValue = listen(listen_fd, BACKLOG);
		ASSERT_INT_EQ(retValue, 0);
		connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(connect_fd, -1);
		
		TEST_DONE();
	}

	{
		TEST_START("non blocking accept and connect");

		retValue = set_nonblock(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		accept_fd = accept(listen_fd, NULL, NULL);
		ASSERT_INT_EQ(accept_fd, -1);
		ASSERT_INT_EQ(errno, EAGAIN);
		retValue = set_nonblock(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		/* connect is too fast to block
		ASSERT_INT_EQ(ret, -1);
		ASSERT_INT_EQ(errno, EINPROGRESS); */
		ASSERT_INT_EQ(retValue, 0);
		retValue = unset_nonblock(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		accept_fd = accept(listen_fd, NULL, NULL);
		ASSERT_INT_NE(accept_fd, -1);
		retValue = close(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	{
		TEST_START("non blocking recv");

		retValue = set_nonblock(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EAGAIN);
		retValue = unset_nonblock(accept_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = send(accept_fd, small_send_buf, strlen(small_send_buf), 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		retValue = unset_nonblock(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = recv(connect_fd, small_recv_buf, SMALL_RECV_BUF_SIZE, 0);
		ASSERT_INT_EQ(retValue, strlen(small_send_buf));
		small_recv_buf[retValue] = '\0';
		ASSERT_STRING_EQ(small_send_buf, small_recv_buf);
		memset(small_recv_buf, 0, sizeof(small_recv_buf));
		
		TEST_DONE();
	}

	{
		TEST_START("non blocking send");
		
		send_buf = malloc(10 * 1024);
		ASSERT_PTR_NE(send_buf, NULL);
		retValue = set_nonblock(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = 1;
		while (retValue > 0) {
			retValue = send(connect_fd, send_buf, 10 * 1024, 0);
		}
		ASSERT_INT_EQ(retValue, -1);
		ASSERT_INT_EQ(errno, EAGAIN);
		retValue = close(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = close(accept_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	free(send_buf);
	freeaddrinfo(servinfo);
}

void 
socket_select_tests() {
	int s, r;
	int num_bytes = 1024 * 1024 * 2; //2 MB
	int bytes_sent = 0;
	int bytes_received = 0;
	int seed = 326;
	int eagain_results = 0;

	{
		TEST_START("select listen");

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		retValue = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo);
		ASSERT_INT_EQ(retValue, 0);
		listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(listen_fd, -1);
		retValue = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		retValue = listen(listen_fd, BACKLOG);
		ASSERT_INT_EQ(retValue, 0);
		connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(connect_fd, -1);
		retValue = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		retValue = set_nonblock(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		time_val.tv_sec = 60;
		time_val.tv_usec = 0;
		FD_ZERO(&read_set);
		FD_SET(listen_fd, &read_set);
		retValue = select(listen_fd + 1, &read_set, NULL, NULL, &time_val);
		ASSERT_INT_NE(retValue, -1);
		ASSERT_INT_EQ(FD_ISSET(listen_fd, &read_set), 1);
		accept_fd = accept(listen_fd, NULL, NULL);
		ASSERT_INT_NE(accept_fd, -1);
		retValue = close(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	{
		TEST_START("select send and recv");

		s = accept_fd;
		r = connect_fd;
		retValue = set_nonblock(s);
		ASSERT_INT_EQ(retValue, 0);
		retValue = set_nonblock(r);
		ASSERT_INT_EQ(retValue, 0);
		send_buf = malloc(num_bytes);
		recv_buf = malloc(num_bytes + 1);
		ASSERT_PTR_NE(send_buf, NULL);
		ASSERT_PTR_NE(recv_buf, NULL);
		prep_input_buffer(send_buf, num_bytes, 17);
		FD_ZERO(&read_set);
		FD_ZERO(&write_set);
		FD_SET(s, &write_set);
		FD_SET(r, &read_set);
		while (-1 != select(max(r, s) + 1, &read_set, &write_set, NULL, &time_val)) {
			if (FD_ISSET(s, &write_set)) {
				while ((bytes_sent < num_bytes) && ((retValue = send(s, send_buf + bytes_sent, num_bytes - bytes_sent, 0)) > 0))
					bytes_sent += retValue;
				if (bytes_sent < num_bytes) {
					ASSERT_INT_EQ(retValue, -1);
					ASSERT_INT_EQ(errno, EAGAIN);
					eagain_results++;
				}
			}

			if (FD_ISSET(r, &read_set)) {
				while ((retValue = recv(r, recv_buf + bytes_received, num_bytes - bytes_received + 1, 0)) > 0)
					bytes_received += retValue;
				if (retValue == 0)
					break;
				ASSERT_INT_EQ(retValue, -1);
				ASSERT_INT_EQ(errno, EAGAIN);
				eagain_results++;
			}

			if (bytes_sent < num_bytes)
				FD_SET(s, &write_set);
			else {
				FD_CLR(s, &write_set);
				retValue = shutdown(s, SD_SEND);
				ASSERT_INT_EQ(retValue, 0);
			}
			FD_SET(r, &read_set);
		}

		/*ensure that we hit send and recv paths that returned EAGAIN. Else it would not have touched the async paths*/
		/*if this assert is being hit, then num_bytes is too small. up it*/
		ASSERT_INT_GT(eagain_results, 0);
		ASSERT_INT_EQ(bytes_sent, bytes_received);
		ASSERT_INT_EQ(memcmp(send_buf, recv_buf, num_bytes), 0);
		retValue = close(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = close(accept_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	freeaddrinfo(servinfo);
}

void 
socket_typical_ssh_payload_tests() {
	int s, r;
	int max_bytes = 1024 * 700; //700KB
	int max_packetsize = 1024 * 5, bytes_sent = 0;
	int packets_sent = 0;
	int packets_received = 0;
	int send_packet_remaining = 0, recv_packet_remaining = 0;
	int eagain_results = 0;

	{
		TEST_START("connection setup");
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		retValue = getaddrinfo("127.0.0.1", PORT, &hints, &servinfo);
		ASSERT_INT_EQ(retValue, 0);
		listen_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(listen_fd, -1);
		retValue = bind(listen_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		retValue = listen(listen_fd, BACKLOG);
		ASSERT_INT_EQ(retValue, 0);
		connect_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		ASSERT_INT_NE(connect_fd, -1);
		retValue = connect(connect_fd, servinfo->ai_addr, servinfo->ai_addrlen);
		ASSERT_INT_EQ(retValue, 0);
		accept_fd = accept(listen_fd, NULL, NULL);
		ASSERT_INT_NE(accept_fd, -1);
		retValue = close(listen_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	{
		TEST_START("select send and recv packets");

		r = accept_fd;
		s = connect_fd;
		retValue = set_nonblock(s);
		ASSERT_INT_EQ(retValue, 0);
		retValue = set_nonblock(r);
		ASSERT_INT_EQ(retValue, 0);
		send_buf = malloc(max_bytes);
		recv_buf = malloc(max_bytes + 1);
		ASSERT_PTR_NE(send_buf, NULL);
		ASSERT_PTR_NE(recv_buf, NULL);
		FD_ZERO(&read_set);
		FD_ZERO(&write_set);
		FD_SET(s, &write_set);
		FD_SET(r, &read_set);

		int total = 0;
		while (-1 != select(max(r, s) + 1, &read_set, &write_set, NULL, &time_val)) {
			if (FD_ISSET(s, &write_set)) {
				while ((send_packet_remaining) && ((retValue = send(s, send_buf, send_packet_remaining, 0)) > 0)) {
					send_packet_remaining -= retValue;
					bytes_sent += retValue;
				}

				if (send_packet_remaining) {
					ASSERT_INT_EQ(retValue, -1);
					ASSERT_INT_EQ(errno, EAGAIN);
				}
				else if (bytes_sent < max_bytes) {
					send_packet_remaining = (rand()*(max_packetsize - 100) / RAND_MAX) + 100;
					retValue = send(s, &send_packet_remaining, 4, 0);
					if (retValue == -1) {
						send_packet_remaining = 0; //we'll try again when io is ready
					}
					else if (retValue < 4)
						/*unfortunate - sent half the header, we'll bail the test out*/
						ASSERT_INT_EQ(1, 0);
					else {
						ASSERT_INT_EQ(retValue, 4);
						packets_sent++;
						//printf("sending packet of size %d\n", send_packet_remaining);
					}
				}
			}

			if (FD_ISSET(r, &read_set)) {
				while (recv_packet_remaining && ((retValue = recv(r, recv_buf, recv_packet_remaining, 0)) > 0)) {
					recv_packet_remaining -= retValue;
				}

				if (recv_packet_remaining) {
					ASSERT_INT_EQ(retValue, -1);
					ASSERT_INT_EQ(errno, EAGAIN);
				}
				else {
					retValue = recv(r, &recv_packet_remaining, 4, 0);
					if (retValue == -1) {
						ASSERT_INT_EQ(retValue, -1);
						ASSERT_INT_EQ(errno, EAGAIN);
					}
					else if (retValue == 0)
						break;
					else if (retValue < 4)
						/*unfortunate.. read partial header, bail out*/
						ASSERT_INT_EQ(1, 0);
					else {
						ASSERT_INT_EQ(retValue, 4);
						packets_received++;
						//printf("recevied packet of size %d\n", recv_packet_remaining);
					}
				}
			}

			if ((bytes_sent >= max_bytes) && (send_packet_remaining == 0)) {
				FD_CLR(s, &write_set);
				retValue = shutdown(s, SD_SEND);
				ASSERT_INT_EQ(retValue, 0);
			}
			else
				FD_SET(s, &write_set);

			FD_SET(r, &read_set);
		}

		ASSERT_INT_EQ(packets_sent, packets_received);
		retValue = close(connect_fd);
		ASSERT_INT_EQ(retValue, 0);
		retValue = close(accept_fd);
		ASSERT_INT_EQ(retValue, 0);
		
		TEST_DONE();
	}

	freeaddrinfo(servinfo);
}

void
socket_tests()
{
	socket_fd_tests();
	socket_blocking_io_tests();
	socket_nonblocking_io_tests();
	socket_select_tests();
	socket_typical_ssh_payload_tests();
}
