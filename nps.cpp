#include "nps.h"
#include "ui_nps.h"

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

