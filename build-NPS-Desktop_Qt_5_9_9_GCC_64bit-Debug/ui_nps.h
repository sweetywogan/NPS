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
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_nps
{
public:
    QWidget *centralwidget;
    QLabel *label;
    QWidget *verticalLayoutWidget;
    QVBoxLayout *verticalLayout;
    QPushButton *startButton;
    QPushButton *clearButton;
    QLabel *label_4;
    QLabel *label_3;
    QTextBrowser *textBrowser;
    QWidget *horizontalLayoutWidget;
    QHBoxLayout *horizontalLayout_3;
    QLabel *label_2;
    QLineEdit *filterLine;
    QTreeWidget *treeWidget;
    QLabel *label_5;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *nps)
    {
        if (nps->objectName().isEmpty())
            nps->setObjectName(QStringLiteral("nps"));
        nps->resize(1868, 1260);
        centralwidget = new QWidget(nps);
        centralwidget->setObjectName(QStringLiteral("centralwidget"));
        label = new QLabel(centralwidget);
        label->setObjectName(QStringLiteral("label"));
        label->setGeometry(QRect(1590, 30, 171, 34));
        verticalLayoutWidget = new QWidget(centralwidget);
        verticalLayoutWidget->setObjectName(QStringLiteral("verticalLayoutWidget"));
        verticalLayoutWidget->setGeometry(QRect(1410, 97, 381, 1081));
        verticalLayout = new QVBoxLayout(verticalLayoutWidget);
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        verticalLayout->setContentsMargins(0, 0, 0, 0);
        startButton = new QPushButton(verticalLayoutWidget);
        startButton->setObjectName(QStringLiteral("startButton"));
        startButton->setEnabled(true);

        verticalLayout->addWidget(startButton);

        clearButton = new QPushButton(verticalLayoutWidget);
        clearButton->setObjectName(QStringLiteral("clearButton"));

        verticalLayout->addWidget(clearButton);

        label_4 = new QLabel(verticalLayoutWidget);
        label_4->setObjectName(QStringLiteral("label_4"));

        verticalLayout->addWidget(label_4);

        label_3 = new QLabel(verticalLayoutWidget);
        label_3->setObjectName(QStringLiteral("label_3"));

        verticalLayout->addWidget(label_3);

        textBrowser = new QTextBrowser(verticalLayoutWidget);
        textBrowser->setObjectName(QStringLiteral("textBrowser"));

        verticalLayout->addWidget(textBrowser);

        horizontalLayoutWidget = new QWidget(centralwidget);
        horizontalLayoutWidget->setObjectName(QStringLiteral("horizontalLayoutWidget"));
        horizontalLayoutWidget->setGeometry(QRect(60, 27, 1261, 81));
        horizontalLayout_3 = new QHBoxLayout(horizontalLayoutWidget);
        horizontalLayout_3->setObjectName(QStringLiteral("horizontalLayout_3"));
        horizontalLayout_3->setContentsMargins(0, 0, 0, 0);
        label_2 = new QLabel(horizontalLayoutWidget);
        label_2->setObjectName(QStringLiteral("label_2"));

        horizontalLayout_3->addWidget(label_2);

        filterLine = new QLineEdit(horizontalLayoutWidget);
        filterLine->setObjectName(QStringLiteral("filterLine"));

        horizontalLayout_3->addWidget(filterLine);

        treeWidget = new QTreeWidget(centralwidget);
        treeWidget->setObjectName(QStringLiteral("treeWidget"));
        treeWidget->setGeometry(QRect(60, 167, 1261, 1011));
        label_5 = new QLabel(centralwidget);
        label_5->setObjectName(QStringLiteral("label_5"));
        label_5->setGeometry(QRect(60, 120, 601, 41));
        nps->setCentralWidget(centralwidget);
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
        clearButton->setText(QApplication::translate("nps", "\346\270\205\351\231\244", Q_NULLPTR));
        label_4->setText(QString());
        label_3->setText(QApplication::translate("nps", "\347\263\273\347\273\237\346\227\245\345\277\227\357\274\232", Q_NULLPTR));
        label_2->setText(QApplication::translate("nps", "\350\277\207\346\273\244\350\247\204\345\210\231\357\274\232", Q_NULLPTR));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget->headerItem();
        ___qtreewidgetitem->setText(4, QApplication::translate("nps", "length", Q_NULLPTR));
        ___qtreewidgetitem->setText(3, QApplication::translate("nps", "protocol", Q_NULLPTR));
        ___qtreewidgetitem->setText(2, QApplication::translate("nps", "destination", Q_NULLPTR));
        ___qtreewidgetitem->setText(1, QApplication::translate("nps", "source", Q_NULLPTR));
        ___qtreewidgetitem->setText(0, QApplication::translate("nps", "num", Q_NULLPTR));
        label_5->setText(QApplication::translate("nps", "\346\225\260\346\215\256\345\214\205\344\277\241\346\201\257\357\274\232(\346\211\223\345\274\200\345\217\257\344\273\216\346\237\245\347\234\213\350\257\246\347\273\206\344\277\241\346\201\257)", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class nps: public Ui_nps {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_NPS_H
