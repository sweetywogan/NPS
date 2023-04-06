#include "pcap_thread.h"
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"
#include "pcap_thread.h"

#define PROM 1
//promiscuous mode

extern char filter[128]; //过滤条件
char *dev; //抓包设备
extern int number;

pcap_t *pcap;
struct bpf_program bp;

void pcap_thread::run()
{
    sniffer();
}

void pcap_thread::sniffer()
{
    QString info_res;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    info_res="Finding deveice ......\n";
    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        info_res+="No device has been found!\n";
        printf("No device has been found! \n");
    }
    dev = allDev -> name;
    info_res+=QString("Find the deveice:%2\n").arg(dev);

    //打开设备网络
    info_res+="Opening the device ......\n";
    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);
    if(pcap == nullptr)
    {
        info_res+="Open error:";
        info_res+=(errbuf);
        printf("Open error: %s\n", errbuf);
    }else{
        info_res+="Device opened!\n";
    }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        info_res+=QString("Could not found netmask for device %2!\n").arg(dev);
        printf("Could not found netmask for device %s!\n", dev);
        net = 0;
        mask = 0;
    }

    //读取过滤条件
    if(filter != nullptr && filter[0] != '\0')
    {
        if(pcap_compile(pcap, &bp, filter, 0, net) == -1) //编译
        {
            printf("Could not parse filter!\n");
            info_res+=(QString("Could not parse filter!\n"));
            exit(-2);
        }
        if(pcap_setfilter(pcap, &bp) == -1) //安装
        {
            printf("Could not install filter!\n");
            info_res+=(QString("Could not install filter!\n"));
            exit(-2);
        }
    }
    //开始抓取
    info_res+="正在抓包 ... ...\n";
    emit(dataReady(info_res,0));

    pcap_dispatch(pcap, -1, loop_callback,(u_char *)this);

    pcap_close(pcap);

}

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    pcap_thread *pcapthread = (pcap_thread *)args;
    analyze analyze;

    QString packet_analyze_res;
    packet_analyze_res.clear();

    int length = header -> caplen;

    printf("#########################################\n");
    printf("~~~~~~~~~~~~~device: %s~~~~~~~~~~~~~\n", dev);
    printf("~~~~~~~~~~~~~filter: %s~~~~~~~~~~~~~\n", filter);
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("num: %d\n", ++number);
    printf("packet length: %d\n", length);

    packet_analyze_res+="num:"+QString::number(number);
    packet_analyze_res+="@";

    struct ethernet *eHead;
    eHead = (struct ethernet*)packet;
    char tmp[3] = {0};
    printf("************ 数据链路层 ************\n");
    printf("Mac source: ");
    packet_analyze_res += "Mac source: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
            packet_analyze_res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostS[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
            packet_analyze_res += tmp;
        }
    }
    printf("Mac destination: ");
    packet_analyze_res += "Mac destination: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr - 1 == i)
        {
            printf("%02x\n", eHead -> etherHostD[i]);
            sprintf(tmp, "%02x", eHead -> etherHostD[i]);
            packet_analyze_res += tmp;
        }
        else
        {
            printf("%02x:", eHead -> etherHostD[i]);
            sprintf(tmp, "%02x:", eHead -> etherHostD[i]);
            packet_analyze_res += tmp;
        }
    }
    packet_analyze_res+="@";

    u_short protocol_num;
    QString protocol;

    protocol_num = ntohs(eHead -> etherType);

    printf("************ 网络层 ************\n");
    switch (protocol_num)
        {
        case 0x0800:
            printf("#######IPv4!\n");
            packet_analyze_res += "IPv4!\n";
            packet_analyze_res += analyze.ipAnalyze(args, header, packet);
            break;
        case 0x0806:
            printf("#######ARP!\n");
            packet_analyze_res += "ARP!\n";
            packet_analyze_res += analyze.arpAnalyze(args, header, packet);
            protocol="ARP";
            break;
        case 0x0835:
            printf("#######RARP!\n");
            packet_analyze_res += "RARP!\n";
            protocol="RARP";
            break;
        case 0x08DD:
            printf("#######IPv6!\n");
            packet_analyze_res += "IPv6!\n";
            protocol="IPv6";
            break;
        default:
            printf("Other network layer protocol!\n");
            packet_analyze_res += "Other network layer protocol";
            protocol="Other network layer protocol";
            break;
        }

        packet_analyze_res+="@";
        packet_analyze_res+=QString::number(length);

        QString mac_raw_res;
        printf("原始数据包：\n");
        for(int i = 0; i < header->len; i++)
        {
            printf("%02x ", packet[i]);
            sprintf(tmp, "%02x ", packet[i]);
            mac_raw_res += tmp;
            if((i+1) % 16 ==0)
            {
                printf("\n");
                sprintf(tmp, "\n");
                mac_raw_res += tmp;
            }
        }

        printf("\n");

        packet_analyze_res+="@";
        packet_analyze_res+=mac_raw_res;

        printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
        printf("#########################################\n\n");

        emit(pcapthread->dataReady(packet_analyze_res,1));

}
