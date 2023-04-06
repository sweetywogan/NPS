#ifndef PCAP_THREAD_H
#define PCAP_THREAD_H

#include <QObject>
#include <QThread>

class pcap_thread : public QThread
{
    Q_OBJECT

signals:
    void dataReady(QString str,int flag);

protected:
    void run();

    void sniffer();
};

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif // PCAP_THREAD_H
