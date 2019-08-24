#include "include.h"

char ** global_argv = nullptr;
uint8_t global_client_ip[4];
uint8_t global_server_ip[4];

unsigned char global_packet[10000];
int global_ret = 0;
uint16_t global_id = 0x1000;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ret = nfq_get_payload(tb, &data);

    //*****************************************************************//

    Ip * data_ip_header = (Ip *)data;
    int ip_size = (data_ip_header->VHL & 0x0F) * 4;
    Tcp * data_tcp_header = (Tcp *)(data + ip_size);
    uint8_t flag = data_tcp_header->flag & 0x3f;


    //---------Is Fake packet?-------------------------------------

    if(ntohs(data_tcp_header->d_port) == 0xabcd && flag == 0x02 && ntohs(data_ip_header->Id) == 0x1234)
    {
        printf("\nLet's Decapsulation\n");

        Ip * ip_header = (Ip *)global_packet;

        memcpy(global_packet, data + 40, ret - 40);

        memcpy(ip_header->s_ip, global_server_ip, 4);

        calIPChecksum(global_packet);


        global_ret = ret - 40;

        dump(global_packet, global_ret);
    }

    //----------------------------------------------------------

    //----------make fake header--------------------------------

    else
    {
        printf("\nGO GO FAKE !!!\n");
        Ip * ip_header = (Ip *)global_packet;
        Tcp * tcp_header = (Tcp *)(global_packet + 20);

        memcpy(global_packet + 40, data, ret);

        ip_header->VHL = 0x45;
        ip_header->TOS = 0x00;
        ip_header->Total_LEN = htons(uint16_t(ret+40));
        ip_header->Id = htons(0x1234);

        ip_header->Fragment = htons(0x4000);
        ip_header->TTL = 0x40;
        ip_header->protocol = 0x06;
        memcpy(ip_header->s_ip, global_server_ip, 4);
        memcpy(ip_header->d_ip, global_client_ip, 4);

        tcp_header->s_port = htons(0xabcd);
        tcp_header->d_port = htons(0xabcd);
        tcp_header->seq = htonl(1);
        tcp_header->ack = htonl(1);
        tcp_header->OFF = 0x50;
        tcp_header->flag = 0x02;
        tcp_header->win_size = htons(0x1212);
        tcp_header->urg_pointer = 0;

        calIPChecksum(global_packet);
        calTCPChecksum(global_packet, ret + 40);


        global_ret = ret + 40;
    }

    //----------------------------------------------------------





    //*****************************************************************//
    fputc('\n', stdout);

    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    //    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, global_ret, global_packet);
}

int main(int argc, char **argv)
{

    TCP_connection();

    char buffer[BUF_LEN];
    struct sockaddr_in server_addr, client_addr;
    char temp[20];
    int server_fd, client_fd;
    //server_fd, client_fd : 각 소켓 번호
    int len, msg_size;

    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {// 소켓 생성
        printf("Server : Can't open stream socket\n");
        exit(0);
    }
    memset(&server_addr, 0x00, sizeof(server_addr));
    //server_Addr 을 NULL로 초기화

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(0xabcd);
    //server_addr 셋팅

    if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0)
    {//bind() 호출
        printf("Server : Can't bind local address.\n");
        exit(0);
    }

    if(listen(server_fd, 5) < 0)
    {//소켓을 수동 대기모드로 설정
        printf("Server : Can't listening connect.\n");
        exit(0);
    }

    memset(buffer, 0x00, sizeof(buffer));
    printf("Server : wating connection request.\n");
    len = sizeof(client_addr);

        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t*)&len);
        if(client_fd < 0)
        {
            printf("Server: accept failed.\n");
            exit(0);
        }
        inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
        printf("Server : %s client connected.\n", temp);





    //**************************************************************
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    char * dev = "wlan0";
    GET_my_ip(dev, global_server_ip);
    inet_pton(AF_INET, argv[1], global_client_ip);



    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            //            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
