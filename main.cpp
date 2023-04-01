#include "nps.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    nps w;
    w.show();
    return a.exec();
}
