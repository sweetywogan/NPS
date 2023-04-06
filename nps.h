#ifndef NPS_H
#define NPS_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class nps; }
QT_END_NAMESPACE

class nps : public QMainWindow
{
    Q_OBJECT

public:
    Ui::nps *ui;
    nps(QWidget *parent = nullptr);
    ~nps();

private slots:
    void on_startButton_clicked();
    void on_clearButton_clicked();
    void updateData(QString str,int flag);
    void set_filter();
};
#endif // NPS_H
