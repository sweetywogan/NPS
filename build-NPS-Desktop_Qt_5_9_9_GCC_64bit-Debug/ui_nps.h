/********************************************************************************
** Form generated from reading UI file 'nps.ui'
**
** Created by: Qt User Interface Compiler version 5.9.9
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_NPS_H
#define UI_NPS_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_nps
{
public:
    QWidget *centralwidget;
    QLabel *label;
    QPushButton *startButton;
    QPushButton *stopButton;
    QTextBrowser *textBrowser;
    QPushButton *clearButton;
    QTreeWidget *treeWidget;
    QLineEdit *filterLine;
    QLabel *label_2;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *nps)
    {
        if (nps->objectName().isEmpty())
            nps->setObjectName(QStringLiteral("nps"));
        nps->resize(1721, 1313);
        centralwidget = new QWidget(nps);
        centralwidget->setObjectName(QStringLiteral("centralwidget"));
        label = new QLabel(centralwidget);
        label->setObjectName(QStringLiteral("label"));
        label->setGeometry(QRect(1520, 20, 171, 34));
        startButton = new QPushButton(centralwidget);
        startButton->setObjectName(QStringLiteral("startButton"));
        startButton->setGeometry(QRect(920, 60, 170, 48));
        stopButton = new QPushButton(centralwidget);
        stopButton->setObjectName(QStringLiteral("stopButton"));
        stopButton->setEnabled(false);
        stopButton->setGeometry(QRect(1120, 60, 170, 48));
        textBrowser = new QTextBrowser(centralwidget);
        textBrowser->setObjectName(QStringLiteral("textBrowser"));
        textBrowser->setGeometry(QRect(40, 910, 1241, 311));
        clearButton = new QPushButton(centralwidget);
        clearButton->setObjectName(QStringLiteral("clearButton"));
        clearButton->setGeometry(QRect(1320, 60, 170, 48));
        treeWidget = new QTreeWidget(centralwidget);
        treeWidget->setObjectName(QStringLiteral("treeWidget"));
        treeWidget->setGeometry(QRect(40, 150, 1661, 681));
        filterLine = new QLineEdit(centralwidget);
        filterLine->setObjectName(QStringLiteral("filterLine"));
        filterLine->setGeometry(QRect(180, 70, 631, 42));
        label_2 = new QLabel(centralwidget);
        label_2->setObjectName(QStringLiteral("label_2"));
        label_2->setGeometry(QRect(30, 70, 141, 34));
        nps->setCentralWidget(centralwidget);
        menubar = new QMenuBar(nps);
        menubar->setObjectName(QStringLiteral("menubar"));
        menubar->setGeometry(QRect(0, 0, 1721, 48));
        nps->setMenuBar(menubar);
        statusbar = new QStatusBar(nps);
        statusbar->setObjectName(QStringLiteral("statusbar"));
        nps->setStatusBar(statusbar);

        retranslateUi(nps);

        QMetaObject::connectSlotsByName(nps);
    } // setupUi

    void retranslateUi(QMainWindow *nps)
    {
        nps->setWindowTitle(QApplication::translate("nps", "nps", Q_NULLPTR));
        label->setText(QApplication::translate("nps", "shu\342\200\230s sniffer", Q_NULLPTR));
        startButton->setText(QApplication::translate("nps", "\345\274\200\345\247\213", Q_NULLPTR));
        stopButton->setText(QApplication::translate("nps", "\345\201\234\346\255\242", Q_NULLPTR));
        clearButton->setText(QApplication::translate("nps", "\346\270\205\351\231\244", Q_NULLPTR));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget->headerItem();
        ___qtreewidgetitem->setText(4, QApplication::translate("nps", "length", Q_NULLPTR));
        ___qtreewidgetitem->setText(3, QApplication::translate("nps", "protocol", Q_NULLPTR));
        ___qtreewidgetitem->setText(2, QApplication::translate("nps", "destination", Q_NULLPTR));
        ___qtreewidgetitem->setText(1, QApplication::translate("nps", "source", Q_NULLPTR));
        ___qtreewidgetitem->setText(0, QApplication::translate("nps", "num", Q_NULLPTR));
        label_2->setText(QApplication::translate("nps", "\350\277\207\346\273\244\350\247\204\345\210\231\357\274\232", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class nps: public Ui_nps {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_NPS_H
