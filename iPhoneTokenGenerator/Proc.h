#ifndef PROC_H
#define PROC_H

#include <QtCore>
#include <QObject>

class Proc : QProcess
{
    Q_OBJECT
public:
    explicit Proc(QObject *parent = 0);
    ~Proc();

    void processCmd(QString cmd, QStringList arguments = QStringList());
    void waitCmd(QString cmd, QStringList arguments = QStringList());

    void stop();

    QByteArray getOutput() {return output;}
    QByteArray getError() {return error;}

private slots:
    void readOutputData();
    void readErrorData();

private:
    QByteArray output;
    QByteArray error;
    QEventLoop lock;
};

#endif // PROC_H
