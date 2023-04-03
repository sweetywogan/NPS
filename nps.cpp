#include "nps.h"
#include "ui_nps.h"
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"

#define PROM 1
//promiscuous mode

char filter[128]; //过滤条件
char *dev; //抓包设备
int flowTotal = 0; //总流量计数
int ipv4Flow = 0, ipv6Flow = 0, arpFlow = 0, rarpFlow = 0, pppFlow = 0;
int ipv4Cnt = 0, ipv6Cnt = 0, arpCnt = 0, rarpCnt = 0, pppCnt = 0;
int tcpFlow = 0, udpFlow = 0, icmpFlow = 0;
int tcpCnt = 0, udpCnt = 0, icmpCnt = 0;
int otherCnt = 0, otherFlow = 0;
int num = 0;

pcap_t *pcap;
struct bpf_program bp;

nps::nps(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::nps)
{
    ui->setupUi(this);
    //tree widget
    ui->treeWidget->setHeaderLabels(QStringList() << "num" << "source" << "destination" << "protocol" << "length");
    ui->treeWidget->setColumnWidth(0, 170);
//    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString::number(1) << QString("0.0.0.0") <<QString("1.1.1.1")<<QString("tcp"));
//    ui->treeWidget->addTopLevelItem(topInfo);
}

nps::~nps()
{
    delete ui;
}


void nps::on_startButton_clicked()
{
    ui->textBrowser->append("开始捕获！");
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
    sniffer();

}

void nps::on_stopButton_clicked()
{
    ui->textBrowser->append("停止捕获！");
    ui->stopButton->setEnabled(false);
    ui->startButton->setEnabled(true);
    //关闭设备
    pcap_breakloop(pcap);
    ui->textBrowser->append(QString("Sniffer stop!\n"));
}

void nps::on_clearButton_clicked()
{
    ui->textBrowser->clear();
}

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    Ui::nps *ui = (Ui::nps *)args;
//    int l = (*header).len;
//    printf("Jacked a packet with length of %d\n",l);

    analyze analyze;

    struct ethernet *eHead;
    u_short protocol;
//    char *time = ctime((const time_t*)&header -> ts.tv_sec);

    int flow = header -> caplen;
    flowTotal += flow;

    printf("#########################################\n");
    printf("~~~~~~~~~~~~~device: %s~~~~~~~~~~~~~\n", dev);
    printf("~~~~~~~~~~~~~filter: %s~~~~~~~~~~~~~\n", filter);
    printf("~~~~~~~~~~~~~analyze information~~~~~~~~~~~~~\n");
    printf("num: %d\n", ++num);
    printf("packet length: %d\n", flow);
//    printf("receive time: %s\n", time);
//    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString::number(num) << QString("0.0.0.0") <<QString("1.1.1.1")<<QString("tcp")<<QString("长度：4%").arg(flow));
    QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString::number(num) << QString("数据包长度: %1").arg(flow));
    ui->treeWidget->addTopLevelItem(topInfo);

    char tmp[3] = {0};
    QString res;
    for(int i = 0; i < header->len; i++)
    {
        printf("%02x ", packet[i]);
        sprintf(tmp, "%02x ", packet[i]);
        res += tmp;
        if((i+1) % 16 ==0)
        {
            printf("\n");
            sprintf(tmp, "\n");
            res += tmp;
        }
    }
    QTreeWidgetItem *pInfo = new QTreeWidgetItem(QStringList() << "数据包内容" << res);
    topInfo->addChild(pInfo);
    res.clear();

    printf("\n\n");

    eHead = (struct ethernet*)packet;
    printf("************ 数据链路层 ************\n");
    printf("~~~~~~~data link layer~~~~~~~\n");
    printf("Mac source: ");
    res += "Mac source: ";
        for(int i = 0; i < ethernetAddr; i++)
        {
            if(ethernetAddr - 1 == i)
            {
                printf("%02x\n", eHead -> etherHostS[i]);
                sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
                res += tmp;
            }
            else
            {
                printf("%02x:", eHead -> etherHostS[i]);
                sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
                res += tmp;
            }
        }
        printf("Mac destination: ");
        res += "Mac destination: ";
        for(int i = 0; i < ethernetAddr; i++)
        {
            if(ethernetAddr - 1 == i)
            {
                printf("%02x\n", eHead -> etherHostS[i]);
                sprintf(tmp, "%02x\n", eHead -> etherHostS[i]);
                res += tmp;
            }
            else
            {
                printf("%02x:", eHead -> etherHostS[i]);
                sprintf(tmp, "%02x:", eHead -> etherHostS[i]);
                res += tmp;
            }
        }
        QTreeWidgetItem * linkInfo = new QTreeWidgetItem(QStringList() << "数据链路层" << res);
        topInfo->addChild(linkInfo);
        res.clear();

        protocol = ntohs(eHead -> etherType);

//        //pppoe 处理
//        if(protocol == 0x8863)
//        {
//            printf("PPPOE Discovery");
//            analyze.pppAnalyze(arg, header, packet);
//            QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Discovery" << res);
//            topInfo->addChild(pppInfo);
//            res.clear();
//            pppCnt ++;
//            pppFlow += flow;
//        }
//        if(protocol == 0x8864)
//        {
//            printf("PPPOE Session");
//            analyze.pppAnalyze(arg, header, packet);
//            QTreeWidgetItem *pppInfo = new QTreeWidgetItem(QStringList() << "PPPOE Session" << res);
//            topInfo->addChild(pppInfo);
//            res.clear();
//            pppCnt ++;
//            pppFlow += flow;
//        }


        QStringList resList;
        QTreeWidgetItem *netInfo, *transInfo;
        printf("************ 网络层 ************\n");
        printf("~~~~~~network layer~~~~~~\n");
        switch (protocol)
        {
        case 0x0800:
            printf("#######IPv4!\n");
            res += "IPv4!\n";
            res += analyze.ipAnalyze(args, header, packet);
            resList = res.split('#');
            netInfo = new QTreeWidgetItem(QStringList() << "网络层" << resList[0]);
            topInfo->addChild(netInfo);
            transInfo = new QTreeWidgetItem(QStringList() << "传输层" << resList[1]);
            topInfo->addChild(transInfo);
            res.clear();
            resList.clear();
            ipv4Flow += flow;
            ipv4Cnt ++;
            break;
        case 0x0806:
            printf("#######ARP!\n");
            res += "ARP!\n";
            res += analyze.arpAnalyze(args, header, packet);
            arpFlow += flow;
            arpCnt ++;
            break;
        case 0x0835:
            printf("#######RARP!\n");
            res += "RARP!\n";
            rarpFlow += flow;
            rarpCnt ++;
            break;
        case 0x08DD:
            printf("#######IPv6!\n");
            res += "IPv6!\n";
            ipv6Flow += flow;
            ipv6Cnt ++;
            break;
        default:
            printf("Other network layer protocol!\n");
            res += "Other network layer protocol!\n";
            otherCnt ++;
            otherFlow += flow;
            break;
        }
        if(!res.isEmpty())
        {
            netInfo = new QTreeWidgetItem(QStringList() << "网络层" << res);
            topInfo->addChild(netInfo);
            res.clear();
        }

        printf("~~~~~~~~~~~~~Done~~~~~~~~~~~~~\n");
        printf("#########################################\n\n\n");

}

void nps::sniffer()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDev;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    ui->textBrowser->append("Finding deveice ......");
    if(pcap_findalldevs(&allDev, errbuf) == -1)
    {
        ui->textBrowser->append(QString("No device has been found!"));
        printf("No device has been found! \n");
    }
    dev = allDev -> name;
    ui->textBrowser->append(QString("Find the deveice:%2").arg(dev));

    //打开设备网络
    ui->textBrowser->append("Opening the device ......");
    pcap = pcap_open_live(dev, snapLen, PROM, 0, errbuf);
    if(pcap == nullptr)
    {
        ui->textBrowser->insertPlainText(QString("Open error:"));
        ui->textBrowser->append(errbuf);
        printf("Open error: %s\n", errbuf);
    }else{
        ui->textBrowser->append("Device opened!\n");
    }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        ui->textBrowser->insertPlainText(QString("Could not found netmask for device %2!").arg(dev));
        printf("Could not found netmask for device %s!\n", dev);
        net = 0;
        mask = 0;
    }

    QApplication::processEvents();

    char filter_exp[]="";
    if (pcap_compile(pcap, &bp, filter_exp, 0, net) == -1)
    {
        ui->textBrowser->append(QString("couldn't parse filter %s: %s\n").arg(filter_exp).arg(pcap_geterr(pcap)));
    }
    if (pcap_setfilter(pcap, &bp) == -1) {
        ui->textBrowser->append(QString("couldn't install filter %s: %s\n").arg(filter_exp).arg(pcap_geterr(pcap)));
    }


    //读取过滤条件
//    if(!ui->filterLine->text().isEmpty())
//    {
//        strcpy(filter, ui->filterLine->text().toStdString().data());
//        if(pcap_compile(pcap, &bp, filter, 0, net) == -1) //编译
//        {
//            printf("Could not parse filter!\n");
//            ui->textBrowser->append(QString("Could not parse filter!"));
//            exit(-2);
//        }
//        if(pcap_setfilter(pcap, &bp) == -1) //安装
//        {
//            printf("Could not install filter!\n");
//            ui->textBrowser->append(QString("Could not install filter!"));
//            exit(-2);
//        }
//    }

    //开始抓取
    ui->textBrowser->append("Snaping ... ...\n");
    QApplication::processEvents();
    pcap_dispatch(pcap, -1, loop_callback, (u_char *) ui);

    pcap_close(pcap);
}

