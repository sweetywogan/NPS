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
    nps(QWidget *parent = nullptr);
    ~nps();

private:
    Ui::nps *ui;
};
#endif // NPS_H
