#include "analyze.h"
#include <pcap.h>
#include "protocol.h"

extern char filter[128]; //过滤条件
extern char *dev; //抓包设备

//arp协议头分析
QString analyze::arpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct arp *aHead = (struct arp *)(packet + ethernetHead);

    QString res;
    QString ip_res;
    res.clear();
    char tmp[50] = {0};

    if(ntohs(aHead -> arpHardware) == 0x0001)
    {
        printf("Hardware type: %s\n", "Ethernet");
        sprintf(tmp, "Hardware type: %s\n", "Ethernet");
    }
    else
    {
        printf("Hardware type: %s\n", "Unknown");
        sprintf(tmp, "Hardware type: %s\n", "Unknown");
    }
    res += tmp;

    if(ntohs(aHead -> arpProtocol) == 0x0800)
    {
        printf("Protocol type: %s\n", "IPv4");
        sprintf(tmp, "Protocol type: %s\n", "IPv4");
    }
    else
    {
        printf("Protocol type: %s\n", "Unknown");
        sprintf(tmp, "Protocol type: %s\n", "Unknown");
    }
    res += tmp;

    if(ntohs(aHead -> arpOperation) == arpRequest)
    {
        printf("Operation: %s\n", "ARP request");
        sprintf(tmp, "Operation: %s\n", "ARP request");
    }
    else
    {
        printf("Operation: %s\n", "ARP reply");
        sprintf(tmp, "Operation: %s\n", "ARP reply");
    }
    res += tmp;


    printf("MAC source: ");
    res += "MAC source: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr-1 == i)
        {
            printf("%02x", aHead -> arpSM[i]);
            sprintf(tmp, "%02x", aHead -> arpSM[i]);
            res += tmp;
        }else{
            printf("%02x:", aHead -> arpSM[i]);
            sprintf(tmp, "%02x:", aHead -> arpSM[i]);
            res += tmp;
        }
    }


    printf("\nMAC destination: ");
    res += "\nMAC destination: ";
    for(int i = 0; i < ethernetAddr; i++)
    {
        if(ethernetAddr-1 ==i)
        {
            printf("%02x", aHead -> arpDM[i]);
            sprintf(tmp, "%02x", aHead -> arpDM[i]);
            res += tmp;
        }else{
            printf("%02x:", aHead -> arpDM[i]);
            sprintf(tmp, "%02x: ", aHead -> arpDM[i]);
            res += tmp;
        }
    }

    printf("\nIP source:");
    res += "\nIP source:";
    for(int i = 0; i < ipAddr; i++)
    {
        if(ipAddr-1==i){
            printf("%d", aHead -> arpSI[i]);
            sprintf(tmp, "%d", aHead -> arpSI[i]);
            res += tmp;
            ip_res += tmp;
        }else{
            printf("%d.", aHead -> arpSI[i]);
            sprintf(tmp, "%d.", aHead -> arpSI[i]);
            res += tmp;
            ip_res += tmp;
        }
    }

    ip_res += '#';

    printf("\nIP destination:");
    res += "\nIP destination:";
    for(int i = 0; i < ipAddr; i++)
    {
        if(ipAddr-1==i){
            printf("%d", aHead -> arpDI[i]);
            sprintf(tmp, "%d", aHead -> arpDI[i]);
            res += tmp;
            ip_res += tmp;
        }else {
            printf("%d.", aHead -> arpDI[i]);
            sprintf(tmp, "%d.", aHead -> arpDI[i]);
            res += tmp;
            ip_res += tmp;
        }

    }
    ip_res += '#';

    ip_res += "ARP";

    printf("\n");
    return res+'@'+ip_res;
}

//icmp协议头分析
QString analyze::icmpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct icmp *icmpHead = (struct icmp *)(packet + ethernetHead + ipHead(packet));
    u_char icmpType = icmpHead -> icmpType;

    QString res;
    res.clear();
    char tmp[50] = {0};

    printf("\nICMP type: %d  ", icmpHead -> icmpType);
    sprintf(tmp, "\nICMP type: %x  ", icmpHead -> icmpType);
    res += tmp;
    switch (icmpType)
    {
    case 0x08:
        printf("(ICMP request)\n");
        res += "(ICMP request)\n";
        break;
    case 0x00:
        printf("(ICMP response)\n");
        res += "(ICMP response)\n";
        break;
    case 0x11:
        printf("(Timeout!)\n");
        res += "(Timeout!)\n";
        break;
    }
    printf("ICMP code: %d\n", icmpHead -> icmpCode);
    sprintf(tmp, "ICMP code: %x\n", icmpHead -> icmpCode);
    res += tmp;

    printf("ICMP check summary: %d\n", icmpHead -> icmpCkSum);
    sprintf(tmp, "ICMP check summary: %d", icmpHead -> icmpCkSum);
    res += tmp;

    return res;
}

//tcp标志位分析
char *tcpFlagAnalyze(const u_char tcpFlags)
{
    char flags[100] = "";
    if((tcpCWR & tcpFlags) == tcpCWR)
        strncat(flags, "CWR: ", 100);
    if((tcpECE & tcpFlags) == tcpECE)
        strncat(flags, "ECE: ", 100);
    if((tcpURG & tcpFlags) == tcpURG)
        strncat(flags, "URG: ", 100);
    if((tcpACK & tcpFlags) == tcpACK)
        strncat(flags, "ACK: ", 100);
    if((tcpPSH & tcpFlags) == tcpPSH)
        strncat(flags, "PSH: ", 100);
    if((tcpRST & tcpFlags) == tcpRST)
        strncat(flags, "RST: ", 100);
    if((tcpSYN & tcpFlags) == tcpSYN)
        strncat(flags, "SYN: ", 100);
    if((tcpFIN & tcpFlags) == tcpFIN)
        strncat(flags, "FIN: ", 100);
    flags[99] = '\0';
    return flags;
}

//tcp协议头分析
QString analyze::tcpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct tcp *tHead = (struct tcp *)(packet + ethernetHead + ipHead(packet));

    QString res;
    res.clear();
    char tmp[50] = {0};

    printf("Source port: %d\n", ntohs(tHead -> tcpS));
    sprintf(tmp, "Source port: %d\n", ntohs(tHead -> tcpS));
    res += tmp;

    printf("Destination port: %d\n", ntohs(tHead -> tcpD));
    sprintf(tmp, "Destination port: %d\n", ntohs(tHead -> tcpD));
    res += tmp;

    printf("Sequence number: %d\n", ntohs(tHead -> tcpSeq));
    sprintf(tmp, "Sequence number: %d\n", ntohs(tHead -> tcpSeq));
    res += tmp;

    printf("Acknowledge number: %d\n", ntohs(tHead -> tcpAck));
    sprintf(tmp, "Acknowledge number: %d\n", ntohs(tHead -> tcpAck));
    res += tmp;

    printf("Header length: %d\n", (tHead -> tcpHR & 0xf0) >> 4);
    sprintf(tmp, "Header length: %d\n", (tHead -> tcpHR & 0xf0) >> 4);
    res += tmp;

    printf("Flag: %d\n", tHead -> tcpFlag);
    sprintf(tmp, "Flag: %d\n", tHead -> tcpFlag);
    res += tmp;

    printf("Flags: %d\n", tcpFlagAnalyze(tHead -> tcpFlag));
    sprintf(tmp, "Flags: %d\n", tcpFlagAnalyze(tHead -> tcpFlag));
    res += tmp;

    printf("Window: %d\n", ntohs(tHead -> tcpWin));
    sprintf(tmp, "Window: %d\n", ntohs(tHead -> tcpWin));
    res += tmp;

    printf("Check summary: %d\n", ntohs(tHead -> tcpCkSum));
    sprintf(tmp, "Check summary: %d\n", ntohs(tHead -> tcpCkSum));
    res += tmp;

    printf("Urgent pointer: %d\n", ntohs(tHead -> tcpUrgP));
    sprintf(tmp, "Urgent pointer: %d", ntohs(tHead -> tcpUrgP));
    res += tmp;

    return res;
}

//udp协议头分析
QString analyze::udpAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct udp *uHead = (struct udp *)(packet + ethernetHead + ipHead(packet));

    QString res;
    res.clear();
    char tmp[50] = {0};

    printf("Source port: %d\n", ntohs(uHead -> udpS));
    sprintf(tmp, "Source port: %d\n", ntohs(uHead -> udpS));
    res += tmp;

    printf("Destination port: %d\n", ntohs(uHead -> udpD));
    sprintf(tmp, "Destination port: %d\n", ntohs(uHead -> udpD));
    res += tmp;

    printf("UDP length: %d\n", ntohs(uHead -> udpLen));
    sprintf(tmp, "UDP length: %d\n", ntohs(uHead -> udpLen));
    res += tmp;

    printf("UDP check summary: %d\n", ntohs(uHead -> udpCkSum));
    sprintf(tmp, "UDP check summary: %d", ntohs(uHead -> udpCkSum));
    res += tmp;

    return res;
}

//ip协议头分析
QString analyze::ipAnalyze(u_char *arg, const struct pcap_pkthdr *pcapPkt, const u_char *packet)
{
    struct ip *ipHead;
    ipHead = (struct ip *)(packet + ethernetHead);

    QString res;
    QString ip_res;
    res.clear();
    ip_res.clear();
    char tmp[50] = {0};

    printf("Version: %d\n", (ipHead -> ipHV & 0xf0) >> 4);
    sprintf(tmp, "Version: %d\n", (ipHead -> ipHV & 0xf0) >> 4);
    res += tmp;

    printf("Head Length: %d\n", ipHead -> ipHV & 0x0f);
    sprintf(tmp, "Head Length: %d\n", ipHead -> ipHV & 0x0f);
    res += tmp;

    printf("Type of Service: %d\n", ipHead -> ipTos);
    sprintf(tmp, "Type of Service: %d\n", ipHead -> ipTos);
    res += tmp;

    printf("Total Length: %d\n", ipHead -> ipLen);
    sprintf(tmp, "Total Length: %d\n", ipHead -> ipLen);
    res += tmp;

    printf("Identification: %d\n", ipHead -> ipId);
    sprintf(tmp, "Identification: %d\n", ipHead -> ipId);
    res += tmp;

    printf("Offset: %d\n", ipHead -> ipOffset & 0x1fff);
    sprintf(tmp, "Offset: %d\n", ipHead -> ipOffset & 0x1fff);
    res += tmp;

    printf("Time to Live: %d\n", ipHead -> ipTtl);
    sprintf(tmp, "Time to Live: %d\n", ipHead -> ipTtl);
    res += tmp;

    printf("Protocol: %d\n", ipHead -> ipProtocol);
    sprintf(tmp, "Protocol: %d\n", ipHead -> ipProtocol);
    res += tmp;

    printf("Check Summary: %d\n", ipHead -> ipCkSum);
    sprintf(tmp, "Check Summary: %d\n", ipHead -> ipCkSum);
    res += tmp;


    printf("IP source: ");
    res += "IP source: ";
    for(int i = 0; i < ipAddr; i++)
    {
        if(ipAddr-1==i)
        {
            printf("%d", ipHead -> ipS[i]);
            sprintf(tmp, "%d", ipHead -> ipS[i]);
            res += tmp;
            ip_res += tmp;
        }else
        {
            printf("%d.", ipHead -> ipS[i]);
            sprintf(tmp, "%d.", ipHead -> ipS[i]);
            res += tmp;
            ip_res += tmp;
        }
    }

    ip_res += '#';

    printf("\nIP destination: ");
    res += "\nIP destination: ";
    for(int i = 0; i < ipAddr; i++)
    {
        if(ipAddr-1==i)
        {
            printf("%d", ipHead -> ipD[i]);
            sprintf(tmp, "%d", ipHead -> ipD[i]);
            res += tmp;
            ip_res += tmp;
        }else {
            printf("%d.", ipHead -> ipD[i]);
            sprintf(tmp, "%d.", ipHead -> ipD[i]);
            res += tmp;
            ip_res += tmp;
        }
    }

    ip_res += '#';

    printf("\n");

    u_char protocol = ipHead -> ipProtocol;

    printf("************** 传输层 **************\n");

    switch (protocol)
    {
    case 0x01:
        printf("#######ICMP!\n");
        ip_res += "ICMP";
        res += icmpAnalyze(arg, pcapPkt, packet);
        break;
    case 0x02:
        res += "$";
        printf("#######IGMP!\n");
        res += "IGMP";
        ip_res += "IGMP";
        break;
    case 0x06:
        res += "$";
        printf("#######TCP!\n");
        ip_res += "TCP";
        res += tcpAnalyze(arg, pcapPkt, packet);
        break;
    case 0x11:
        res += "$";
        printf("#######UDP!\n");
        ip_res += "UDP";
        res += udpAnalyze(arg, pcapPkt, packet);
        break;
    default:
        res += "$";
        printf("Other Transport Layer protocol!\n");
        res += "Other";
        ip_res += "Other";
        break;
    }

    printf("\n");
    return res+"@"+ip_res;
}
