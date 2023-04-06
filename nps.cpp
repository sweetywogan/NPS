#include "nps.h"
#include "ui_nps.h"
#include <pcap.h>
#include "protocol.h"
#include "analyze.h"
#include "pcap_thread.h"

#define PROM 1
//promiscuous mode

char filter[128]; //过滤条件
int number = 0;

nps::nps(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::nps)
{

    ui->setupUi(this);
    //tree widget
    ui->treeWidget->setHeaderLabels(QStringList() << "num" << "IP source" << "IP destination" << "protocol" << "length");
    ui->treeWidget->setColumnWidth(0, 250);
    ui->treeWidget->setColumnWidth(1, 400);
    ui->treeWidget->setColumnWidth(2, 300);
    ui->treeWidget->setColumnWidth(3, 150);
    ui->treeWidget->setColumnWidth(4, 100);

}

nps::~nps()
{
    delete ui;
}

//更新ui
void nps::updateData(QString str,int flag)
{
    if(flag==0)
    {
        ui->textBrowser->append(str);
    }else if(flag==1){
        QStringList strList = str.split('@');
        QString num = strList[0];
        QString mac_res = strList[1];
        QString netandtran_res = strList[2];
        QString head_item = strList[3];
        QString length = strList[4];
        QString raw_res = strList[5];

        QStringList headList = head_item.split('#');
        QString ipsource = headList[0];
        QString ipdestination = headList[1];
        QString protocol = headList[2];

        QTreeWidgetItem * topInfo = new QTreeWidgetItem(QStringList() << QString(num) << QString(ipsource) << QString(ipdestination) << QString(protocol) << QString(length));
        ui->treeWidget->addTopLevelItem(topInfo);

        QTreeWidgetItem *linkInfo = new QTreeWidgetItem(QStringList() << "数据链路层" << mac_res);
        topInfo->addChild(linkInfo);

        if(str.contains(QChar('$')))
        {
            QStringList netList = netandtran_res.split('$');
            QString net_res = netList[0];
            QString tran_res = netList[1];
            QTreeWidgetItem *netInfo = new QTreeWidgetItem(QStringList() << "网络层" << net_res);
            QTreeWidgetItem *transInfo = new QTreeWidgetItem(QStringList() << "传输层" << tran_res);
            topInfo->addChild(netInfo);
            topInfo->addChild(transInfo);
        }else{
            QTreeWidgetItem *netandtransInfo = new QTreeWidgetItem(QStringList() << "网络层" << netandtran_res);
            topInfo->addChild(netandtransInfo);
        }

        QTreeWidgetItem *pInfo = new QTreeWidgetItem(QStringList() << "原始数据包" << raw_res);
        topInfo->addChild(pInfo);
    }

}

void nps::on_startButton_clicked()
{
    pcap_thread *pcapthread = new pcap_thread();
    connect(pcapthread, &pcap_thread::dataReady, this, &nps::updateData);

    if(ui->startButton->text()=="开始"){
        ui->textBrowser->append("开始捕获！");
        ui->startButton->setText("停止");
        set_filter();
        pcapthread->start();
    }else if (ui->startButton->text()=="停止") {
        ui->textBrowser->append("停止捕获！");
        ui->startButton->setText("开始");
        //关闭设备
        pcapthread->wait();
        delete pcapthread;
        ui->textBrowser->append("已抓到数据包"+QString::number(number)+"个\n");
    }
}

void nps::on_clearButton_clicked()
{
    number=0;
    ui->textBrowser->clear();
    ui->treeWidget->clear();
    ui->filterLine->clear();
}

void nps::set_filter()
{
    strcpy(filter,"");
    if(!ui->filterLine->text().isEmpty())
    {
        strcpy(filter, ui->filterLine->text().toUtf8().data());
        ui->textBrowser->append("过滤条件："+QString::fromUtf8(filter));
    }
}

