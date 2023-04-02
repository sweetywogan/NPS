#include "nps.h"
#include "ui_nps.h"
#include <pcap.h>
#include "protocol.h"
//#include "analyze.h"

nps::nps(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::nps)
{
    ui->setupUi(this);
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
}

void nps::on_stopButton_clicked()
{
    ui->textBrowser->append("停止捕获！");
    ui->stopButton->setEnabled(false);
    ui->startButton->setEnabled(true);
}

void nps::on_clearButton_clicked()
{
    ui->textBrowser->clear();
}

