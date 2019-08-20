#include "include.h"

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //saved by network byte order

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct tcphdr *tcph=(struct tcphdr*)(data+iph->ihl*4);

    memcpy(&pseudoheader.srcIP,&iph->saddr,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->daddr,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol;
    pseudoheader.TCPLen=htons(dataLen-(iph->ihl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->check=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));


    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    tcph->check=checksum;

    return checksum;
}

uint16_t calICMPChecksum(uint8_t *data,int dataLen)
{

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct icmphdr *icmph=(struct icmphdr*)(data+iph->ihl*4);

    //Cal ICMP Segement Checksum
    icmph->checksum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)icmph,(dataLen-(iph->ihl*4)));


    uint16_t checksum=tcpHeaderResult;

    checksum=ntohs(checksum^0xffff); //xor checksum
    icmph->checksum=checksum;

    return checksum;
}

uint16_t calUDPChecksum(uint8_t *data, int dataLen)
{
    //make Pseudo Header
    struct Pseudoheader pseudoheader; //save to network byte order

    //init Pseudoheader
    struct iphdr *iph=(struct iphdr*)data;
    struct udphdr *udph=(struct udphdr*)(data+iph->ihl*4);
    memcpy(&pseudoheader.srcIP,&iph->saddr,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->daddr,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->protocol;
    pseudoheader.TCPLen=htons(dataLen-(iph->ihl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    udph->check=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)udph,ntohs(pseudoheader.TCPLen));


    uint16_t checksum;
    int tempCheck;

    if((tempCheck=pseudoResult+tcpHeaderResult)>CARRY)
        checksum=(tempCheck-CARRY) +1;
    else
        checksum=tempCheck;


    checksum=ntohs(checksum^0xffff); //xor checksum
    udph->check=checksum;

    return checksum;
}

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint16_t result;
    int tempChecksum=0;
    int length;
    bool flag=false;
    if((dataLen%2)==0)
        length=dataLen/2;
    else
    {
        length=(dataLen/2)+1;
        flag=true;
    }

    for (int i = 0; i < length; ++i) // cal 2byte unit
    {
        //cout<<hex<<tempChecksum<<" + "<<ntohs(data[i])<<dec<<endl;

        if(i==length-1&&flag) //last num is odd num
            tempChecksum+=ntohs(data[i]&0x00ff);
        else
            tempChecksum+=ntohs(data[i]);

        if(tempChecksum>CARRY)
                tempChecksum=(tempChecksum-CARRY)+1;

    }

    result=tempChecksum;
    return result;
}

uint16_t calIPChecksum(uint8_t* data)
{
    struct iphdr* iph=(struct iphdr*)data;
    iph->check=0;//set Checksum field 0

    uint16_t checksum=calculate((uint16_t*)iph,iph->ihl*4);
    iph->check=htons(checksum^0xffff);//xor checksum

    return checksum;
}
