#include "include.h"

uint8_t global_client_ip[4];
uint8_t global_server_ip[4];
unsigned char global_packet[10000];
int global_ret = 0;


uint16_t global_connection = 0;
uint16_t global_dport;
uint32_t global_Seq_number;
uint32_t global_Ack_number;


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

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, &data);

    //*****************************************************************//

    Ip * data_ip_header = (Ip *)data;
    int ip_size = (data_ip_header->VHL & 0x0F) * 4;
    Tcp * data_tcp_header = (Tcp *)(data + ip_size);
    uint8_t flag = data_tcp_header->flag & 0x3f;

    printf("\nd_port = %04x\tflag = %02x\t Id = %04x\n", ntohs(data_tcp_header->d_port), flag, ntohs(data_ip_header->Id));


    //---------Is SYN packet?--------------------------------------


    if(flag == 0x02 && global_connection == 0)
    {
        printf("Received SYN packet\n");

        memcpy(global_packet, data, ret);
        global_ret = ret;
        return id;
    }





    //---------Is SYN + ACK packet?-------------------------------------

    if(flag == 0x12 && global_connection == 0)
    {
        printf("Send SYN + ACK packet\n");
        printf("Get Seq_num , Ack_num , sport\n");

        global_Seq_number = ntohl(data_tcp_header->seq);
        global_Seq_number += 1;
        global_Ack_number = ntohl(data_tcp_header->ack);
        global_dport = ntohs(data_tcp_header->d_port);

        memcpy(global_packet, data, ret);
        global_ret = ret;

        return id;
    }

    //---------Is ACK packet?-------------------------------------
    if(flag == 0x10 && global_connection == 0)
    {
        printf("Received ACK packet\n");

        memcpy(global_packet, data, ret);
        global_ret = ret;
        global_connection = 1;



        return id;
    }

    //---------Is Encapsulation packet?-------------------------------------

    if(ntohs(data_tcp_header->d_port) == 0xabcd && flag == 0x18 && global_connection == 1)
    {
        printf("Let's Decapsulation\n");

        Ip * ip_header = (Ip *)global_packet;

        memcpy(global_packet, data + 40, ret - 40);

        memcpy(ip_header->s_ip, global_server_ip, 4);

        calIPChecksum(global_packet);

        global_ret = ret - 40;

        dump(global_packet, global_ret);
    }

    //----------------------------------------------------------

    //----------Let's Encapsulation--------------------------------
    else if (global_connection == 1)
    {
        printf("GO GO FAKE !!!\n");
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
        tcp_header->d_port = htons(global_dport);
        tcp_header->seq = htonl(global_Seq_number);
        tcp_header->ack = htonl(global_Ack_number);
        tcp_header->OFF = 0x50;
        tcp_header->flag = 0x18;
        tcp_header->win_size = htons(0x1212);
        tcp_header->urg_pointer = 0;

        calIPChecksum(global_packet);
        calTCPChecksum(global_packet, ret + 40);


        global_ret = ret + 40;
    }
    else
    {
        memcpy(global_packet, data, ret);
        global_ret = ret;

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

//    int arr[2];
//    TCP_connection(arr);

    if(argc != 2)
    {
        printf("Usage: ./tcp_tunneling_server <client_ip> \n");
        return -1;
    }


    //**************************************************************
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    char * dev = "eth1";
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
//    close(arr[0]);
//    close(arr[1]);

    exit(0);
}
