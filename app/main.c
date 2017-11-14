#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <pthread.h>

#include "logger.h"

#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024
#define BUF_SIZE 1024

pthread_mutex_t mutex;
pthread_cond_t cond;
int sockfd;

struct sockaddr_nl nladdr;
struct msghdr msg;
struct iovec iov;
struct nlmsghdr *nlh;

static void dump_nlmsg(struct nlmsghdr *nlh)
{
	int i, j, len;
	unsigned char *data = NLMSG_DATA(nlh);
	int col = 16;
	int datalen = NLMSG_PAYLOAD(nlh, 0);

	printf("User Debug Start===============\n");
	printf("nlmsghdr info (%d):\n", NLMSG_HDRLEN);
	printf("  nlmsg_len\t= %d\n" "  nlmsg_type\t= %d\n"
		"  nlmsg_flags\t= %d\n" "  nlmsg_seq\t= %d\n" "  nlmsg_pid\t= %d\n",
		nlh->nlmsg_len, nlh->nlmsg_type,
		nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);

	printf("nlmsgdata info (%d):\n", datalen);

	for (i = 0; i < datalen; i += col) {
		len = (datalen - i < col) ? (datalen - i) : col;

		printf("  ");
		for (j = 0; j < col; j++) {
			if (j < len)
				printf("%02x ", data[i + j]);
			else
				printf("   ");

		}
		printf("\t");
		for (j = 0; j < len; j++) {
			if (j < len)
				if (isprint(data[i + j]))
					printf("%c", data[i + j]);
				else
					printf(".");
			else
				printf(" ");
		}
		printf("\n");
	}
	printf("User Debug End===============\n");
}


void *send_thread(void *arg)
{
	int ret;
    pthread_cleanup_push(pthread_mutex_unlock,&mutex);
	unsigned long int id1;
	id1=pthread_self(); 
	while(1)
	{
        printf("send_thread is running id =%d\n",id1);
        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond,&mutex);
        printf("send_thread applied the condition\n");
		char testmsg[20] = "hello kernel!";
		ret = send_msg_once(sockfd, &testmsg, sizeof(testmsg));
		if (ret < 0) 
		{
			LOG_ERROR("send_msg_once: send msg failed");
			close(sockfd);
			return EXIT_FAILURE;
		}
        pthread_mutex_unlock(&mutex);
        sleep(4);
	}
    pthread_cleanup_pop(0);
}

void test_reset_msg(void)
{
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

}

int test_recv_msg(int sockfd, char *buf, int len)
{
	int ret;
	LOG_INFO("start to recv message");

	ret = recvmsg(sockfd, (struct msghdr *) &msg, 0);
	if (ret < 0)
	{
		LOG_ERROR("recvmsg: %s", strerror(errno));
		return ret;
	}

	strncpy(buf, NLMSG_DATA(nlh), len - 1);
	buf[len] = '\0';

	dump_nlmsg(nlh);

	return ret;
}

void *rcv_thread(void *arg)
{
	int ret;
	char buf[BUF_SIZE];
	unsigned long int id3;
	id3=pthread_self();
    while(1)
	{	
		sleep(13);
        printf("rcv_thread is running id =%d\n",id3);
        pthread_mutex_lock(&mutex);
        pthread_cond_wait(&cond,&mutex);
        printf("rcv_thread applied the condition\n");
		test_reset_msg();
		ret = test_recv_msg(sockfd, buf, sizeof(buf));
		printf("rcv_thread test_recv_msg.....\n");
		if (ret < 0) 
		{
			LOG_ERROR("send_msg_once: send key failed");
			close(sockfd);
			return EXIT_FAILURE;
		}
        pthread_mutex_unlock(&mutex);
		
    }
}


int send_msg_once(int sockfd, void *str, int str_len)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh;
	int ret;
	int len = str_len;
	nlh = calloc(1, NLMSG_SPACE(len));
	if (!nlh) 
	{
		LOG_ERROR("calloc: alloc nlmsghdr error");
		return -1;
	}
	nlh->nlmsg_len = NLMSG_LENGTH(len);
	nlh->nlmsg_type = 0;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 9527;
	nlh->nlmsg_pid = getpid();
	memcpy(NLMSG_DATA(nlh), str,len);

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	LOG_INFO("start to send message");

	ret = sendmsg(sockfd, (struct msghdr *) &msg, 0);
	if (ret < 0) {
		LOG_ERROR("sendmsg: %s", strerror(errno));
		free(nlh);
		return ret;
	}

	dump_nlmsg(nlh);

	free(nlh);
	return ret;
}

int init_netlink_socket(int protocol)
{
	int sockfd;
	struct sockaddr_nl nladdr;
	int ret;

	sockfd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (sockfd < 0) 
	{
		LOG_ERROR("socket: %s", strerror(errno));
		return -1;
	}

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = getpid();
	nladdr.nl_groups = 0;

	ret = bind(sockfd, (struct sockaddr *) &nladdr, sizeof(nladdr));
	if (ret < 0)
	{
		LOG_ERROR("bind: %s", strerror(errno));
		close(sockfd);
		return ret;
	}

	return sockfd;
}

int main()
{
	int ret;
	char buf[BUF_SIZE];
	char testmsg[20] = "hello kernel!";
	sockfd = init_netlink_socket(NETLINK_TEST);
	if (sockfd < 0) 
	{
		LOG_ERROR("init_netlink_socket: couldn't init netlink socket");
		return EXIT_FAILURE;
	}
	ret = send_msg_once(sockfd, &testmsg, sizeof(testmsg));
	if (ret < 0) 
	{
		LOG_ERROR("send_msg_once: send msg failed");
		close(sockfd);
		return EXIT_FAILURE;
	}
	nlh = calloc(1, NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh) 
	{
		LOG_ERROR("calloc: alloc nlmsghdr error");
		return -1;
	}
	test_reset_msg();
	ret = test_recv_msg(sockfd, buf, sizeof(buf));
	if (ret < 0) 
	{
		LOG_ERROR("test_recv_msg: recv msg failed");
		close(sockfd);
		return EXIT_FAILURE;
	}
	LOG_INFO("receive from kernel: %s", buf);
	pthread_t thid1,thid3;
    printf("condition variable study!\n");
    pthread_mutex_init(&mutex,NULL);
    pthread_cond_init(&cond,NULL);
    pthread_create(&thid1,NULL,(void*)send_thread,NULL);
	pthread_create(&thid3,NULL,(void*)rcv_thread,NULL);
	do{
        pthread_cond_signal(&cond);
    }while(1);
    sleep(20);
	free(nlh);
    pthread_exit(0);
	close(sockfd);
	return EXIT_SUCCESS;
}
