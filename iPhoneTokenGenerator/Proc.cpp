#include "Proc.h"

Proc::Proc(QObject *parent)
    : QProcess(parent)
{
    setProcessChannelMode(QProcess::MergedChannels);
    connect(this, SIGNAL(finished(int, QProcess::ExitStatus)), &lock, SLOT(quit()));
    connect(this, SIGNAL(readyReadStandardOutput()), SLOT(readOutputData()));
    connect(this, SIGNAL(readyReadStandardError()), SLOT(readErrorData()));
}
Proc::~Proc()
{

}

void Proc::processCmd(QString cmd, QStringList arguments)
{
    output.clear();
    error.clear();
    start(cmd, arguments);
    lock.exec();
}
void Proc::waitCmd(QString cmd, QStringList arguments)
{
    output.clear();
    error.clear();
    start(cmd, arguments);
}
void Proc::stop()
{
    terminate();
}

void Proc::readOutputData()
{
    output.append(readAllStandardOutput());
}
void Proc::readErrorData()
{
    error.append(readAllStandardError());
}
