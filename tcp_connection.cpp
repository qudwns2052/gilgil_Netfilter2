#include "tcp_connection.h"

void GET_my_ip(char * dev, uint8_t * my_ip)
{
    /*        Get my IP Address      */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr); // ???????

    close(fd);
    memcpy(my_ip, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);
}

int TCP_connection(char * server_ip)
{
    int s, n;
    struct sockaddr_in server_addr;
    //struct sockaddr_in server_addr : 서버의 소켓주소 구조체
    char _buf[BUF_LEN+1];



    if((s = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {//소켓 생성과 동시에 소켓 생성 유효검사
        printf("can't create socket\n");
        exit(0);
    }

    bzero((char *)&server_addr, sizeof(server_addr));
    //서버의 소켓주소 구조체 server_addr을 NULL로 초기화

    server_addr.sin_family = AF_INET;
    //주소 체계를 AF_INET 로 선택
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    //32비트의 IP주소로 변환
    server_addr.sin_port = htons(0xabcd);
    //daytime 서비스 포트 번호

    connect(s, (struct sockaddr *)&server_addr, sizeof(server_addr));

    return s;

}
