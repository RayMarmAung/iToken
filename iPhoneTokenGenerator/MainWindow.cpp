#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "Ssl.h"

#include <QClipboard>
#include <psapi.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("iToken Dumper");
    setFixedSize(size());
    setWindowIcon(QIcon(":/icon2.png"));

    ui->log->setLog(QStringList() << "Prerequisites$b$d");
    ui->log->setLog(QStringList() << "\n\n- Your device must be jailbroken with" << "Checkra1n$b$d");
    ui->log->setLog(QStringList() << "\n- Install latest" << "iTunes$b" << "version$d");
}

MainWindow::~MainWindow()
{
    proxy.stop();
    delete ui;
}
void MainWindow::on_bt0_clicked()
{
    QClipboard *clipboard = QApplication::clipboard();
    if (!encryptText.isEmpty())
    {
        clipboard->setText(encryptText);
    }
}
void MainWindow::on_bt1_clicked()
{
    if (encryptText.isEmpty())
        return;
    QString path = QFileDialog::getSaveFileName(this, "Save", QString(), "Sophada file (*.sophada)");
    if (path.isEmpty())
        return;
    QFile file(path);
    if (file.open(QFile::WriteOnly | QFile::Truncate))
    {
        file.write(encryptText.toUtf8());
        file.close();
    }
}
void MainWindow::on_bt2_clicked()
{
    ui->log->setLog(QStringList() << "\n\nGathering" << "information$b");

    Proc cmd;
    cmd.processCmd("data/ideviceinfo.exe", QStringList() << "-s");
    QByteArray data = cmd.getOutput();

    if (data.isEmpty())
    {
        ui->log->setState(1);
        return;
    }

    ui->log->setState();
    ui->log->setInfor(QString(), data);
}
void MainWindow::on_bt3_clicked()
{
    Proc cmd;
    encryptText.clear();

    QString account, dsid, token;
    QMultiMap<QString, QString> map;
    QMultiMap<QString, QString> res;
    // get information
    {
        ui->log->setLog(QStringList() << "\n\nGathering" << "information$b");
        cmd.processCmd("data/ideviceinfo.exe", QStringList() << "-s");
        QByteArray result = cmd.getOutput();
        if (QString(result).startsWith("error: ", Qt::CaseInsensitive))
        {
            ui->log->setState(1, QString(result).remove("ERROR: ").trimmed());
            return;
        }
        searchOnStream(cmd.getOutput(), map);
        if (!map.value("ProductVersion").startsWith("13."))
        {
            ui->log->setState(1, QString("Device not supported ios %1").arg(map.value("ProductVersion")));
            return;
        }
        ui->log->setState();
    }
    // kill iproxy
    {
        ui->log->setLog(QStringList() << "\n\nKilling" << "iproxy$b");
        killProcess();
        ui->log->setState();
    }
    // port forward
    {
        ui->log->setLog(QStringList() << "\nForwarding port to" << "2222$b");
        if (!QFileInfo("data/iproxy.exe").exists())
        {
            ui->log->setState(1, "iproxy file not found");
            return;
        }
        proxy.waitCmd("data/iproxy.exe", QStringList() << "2222" << "44");
        ui->log->setState();
    }
    // connecting
    {
        QString path = QDir::toNativeSeparators(QDir::currentPath() + "/data/plink.exe");
        ui->log->setLog(QStringList() << "\nConnecting to" << "device$b");

        QProcess p;
        p.start("cmd.exe /c \"echo y | " + path + " -ssh -P 2222 root@localhost");
        p.waitForFinished();
        //cmd.processCmd("cmd", QStringList() << "/c \"echo y | " + path + " -ssh -P 222 root@localhost\"");
        //QProcess::startDetached("cmd /c \"echo y | " + path + " -ssh -P 2222 root@localhost\"");

        //cmd.processCmd("cmd.exe /c \"echo y | " + path + " -ssh -P 2222 root@localhost\"");
        //qDebug() << cmd.getOutput();

        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "echo" << "connected");
        QString result = QString(cmd.getOutput());
        if (result.compare("connected\n", Qt::CaseInsensitive) != 0)
        {
            ui->log->setState(1, result.mid(result.indexOf(":") + 1).trimmed());
            proxy.stop();
            return;
        }
        ui->log->setState();
    }
    // mount
    {
        ui->log->setLog(QStringList() << "\nMounting" << "filesystem$b");
        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "mount" << "-o" << "rw,union,update" << "/");
        if (!QString(cmd.getOutput()).isEmpty())
        {
            ui->log->setState(1, "failed to mount");
            proxy.stop();
            return;
        }
        ui->log->setState();
    }
    // test binary
    {
        ui->log->setLog(QStringList() << "\nChecking required" << "binaries$b" << "is existed");
        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "test" << "-f" << "/usr/libexec/sqlite3" << "&&" << "test" << "-f" << "/usr/libexec/jlutil" << "&&" << "test" << "-f" << "/usr/libexec/kt" << "&&" << "test" << "-f" << "/usr/libexec/getserial" << "&&" << "echo" << "Skip upload");
        ui->log->setState();
        if (QString(cmd.getOutput()).compare("skip upload\n", Qt::CaseInsensitive) != 0)
        {
            ui->log->setLog(QStringList() << "\nUploading required" << "binaries$b");
            cmd.processCmd("data/pscp.exe", QStringList() << "-scp" << "-r" << "-P" << "2222" << "-pw" << "alpine" << QDir::currentPath() + "/data/mct.tar.gz" << "root@localhost:/usr/libexec/mct.tar.gz");
            cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "cd" << "/usr/libexec" << "&&" << "mount" << "-o" << "rw,union,update" << "/" << "&&" << "tar" << "-xvzf" << "/usr/libexec/mct.tar.gz");
            cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "chmod" << "a+x" << "/usr/libexec/sqlite3" << "/usr/libexec/kt" << "/usr/libexec/getserial" << "/usr/libexec/jlutil");
            ui->log->setState();
        }
    }
    // reading information
    {
        ui->log->setLog(QStringList() << "\nReading" << "information$b");
        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "/usr/libexec/sqlite3" << "/var/mobile/Library/Accounts/Accounts3.sqlite" << "\"select" << "ZUSERNAME" << "from" << "'ZACCOUNT'" << "where" << "'ZACCOUNT'.'ZACCOUNTDESCRIPTION'" << "=" << "'iCloud'\"");
        res.insert("account", QString(cmd.getOutput()).trimmed());
        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "/usr/libexec/jlutil" << "/var/mobile/Library/Preferences/com.apple.icloud.findmydeviced.FMIPAccounts.plist");
        searchDSID(cmd.getOutput(), res);
        if (res.value("dsid").isEmpty())
        {
            ui->log->setState(1, "No dsid found");
            proxy.stop();
            return;
        }

        QByteArray dataToken;
        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "/usr/libexec/kt" << "-f" << "\"com.apple.account.DeviceLocator.find-my-iphone-app-token\"");
        dataToken = cmd.getOutput();
        if (dataToken.isEmpty())
        {
            cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "/usr/libexec/kt" << "-f" << "\"com.apple.account.AppleAccount.find-my-iphone-app-token\"");
            dataToken = cmd.getOutput();
            if (dataToken.isEmpty())
            {
                ui->log->setState(1, "Data token not found");
                proxy.stop();
                return;
            }
        }
        searchOnData(cmd.getOutput(), res);

        cmd.processCmd("data/plink.exe", QStringList() << "-ssh" << "-P" << "2222" << "root@localhost" << "-pw" << "alpine" << "/usr/libexec/getserial" << map.value("UniqueDeviceID"));
        searchOnData2(cmd.getOutput(), res);
        ui->log->setState();
    }
    // encrypt data
    {
        ui->log->setLog(QStringList() << "\nEncrypting" << "information$b");
        QString result, final;
        int i = 0;

        QFile rsaPubFile("data/public.pem");
        if (!rsaPubFile.open(QFile::ReadOnly))
        {
            ui->log->setState(1, "RSA public key not found");
            proxy.stop();
            return;
        }
        QByteArray key = rsaPubFile.readAll();
        rsaPubFile.close();
        if (key.isEmpty())
        {
            ui->log->setState(1, "Failed to load RSA key");
            proxy.stop();
            return;
        }

        for (QMultiMap<QString,QString>::iterator it = res.begin(); it != res.end(); it++)
        {
            if (it.key() == "sn")
                continue;
            QString line = QString("%1: %2").arg(it.key()).arg(it.value());
            if (!result.contains(line))
            {
                if (i > 0)
                {
                    result.append("\n");
                    final.append("\n");
                }
                result.append(line);

                QString encrypt = line;
                if (!Ssl::encryptText(&encrypt, key))
                {
                    ui->log->setState(1, encrypt);
                    proxy.stop();
                    return;
                }
                final.append(encrypt);
                i++;
            }
        }

        final.prepend("Encrypt: ");
        final.prepend("Serial: " + res.value("sn") + "\n");

        encryptText = final;

        ui->log->setState();
        ui->log->setLine();
        ui->log->setLine();
        ui->log->setLog(QStringList() << final + "$b$d");
    }
}

void MainWindow::searchOnStream(QByteArray data, QMultiMap<QString, QString> &map)
{
    QTextStream stream(data);
    while (!stream.atEnd())
    {
        QString line = stream.readLine();
        if (!line.contains(":"))
            continue;
        QString key = QString(line.split(":").at(0)).trimmed();
        QString res = QString(line.split(":").at(1)).trimmed();
        map.insert(key, res);
    }
}
void MainWindow::searchDSID(QByteArray data, QMultiMap<QString, QString> &map)
{
    QTextStream stream(data);
    while (!stream.atEnd())
    {
        QString line = stream.readLine();
        if (line.contains("dsid:"))
        {
            map.insert("dsid", line.mid(line.indexOf(":")+1).trimmed());
            break;
        }
    }
}
void MainWindow::searchOnData(QByteArray data, QMultiMap<QString, QString> &map)
{
    bool account = false, token = false;
    QTextStream stream(data);
    while (!stream.atEnd())
    {
        QString line = stream.readLine();
        if (!line.contains(":"))
            continue;
        QString key = QString(line.split(":").at(0)).remove("\"").trimmed();
        QString val = QString(line.split(":").at(1)).remove("\"").remove(",").trimmed();

        if (key == "Account")
        {
            map.insert("account", val);
            account = true;
        }
        else if (key == "Data")
        {
            map.insert("token", val);
            token = true;
        }

        if (account && token)
            break;
    }
}
void MainWindow::searchOnData2(QByteArray data, QMultiMap<QString, QString> &map)
{
    QString imd, imdm, timezone, serial;
    QTextStream stream(data);
    while (!stream.atEnd())
    {
        QString line = stream.readLine();
        if (line.contains("="))
        {
            QString key = QString(line.split("=").at(0)).remove("\"").trimmed();
            QString val = QString(line.split("=").at(1)).remove("\"").remove(";").trimmed();

            if (key == "X-Apple-I-MD")
                map.insert("xd", val);
            else if (key == "X-Apple-I-MD-M")
                map.insert("xdm", val);
            else if (key == "X-Apple-I-TimeZone")
                map.insert("xzt", val);
            else if (key == "Serial")
                map.insert("sn", val);
        }
        else if (line.contains(":"))
        {
            QString key = QString(line.split(":").at(0)).remove("\"").trimmed();
            QString val = QString(line.split(":").at(1)).remove("\"").remove(",").trimmed();

            if (key == "X-Apple-I-MD")
                map.insert("xd", val);
            else if (key == "X-Apple-I-MD-M")
                map.insert("xdm", val);
            else if (key == "X-Apple-I-TimeZone")
                map.insert("xzt", val);
            else if (key == "Serial")
                map.insert("sn", val);
        }
    }
}
void MainWindow::killProcess()
{
    const int maxProcIds = 1024;
    DWORD procList[maxProcIds];
    DWORD procCount;
    const char *exeName = "iproxy.exe";

    char processName[MAX_PATH];
    if (!EnumProcesses(procList, sizeof(procList), &procCount))
        return;

    procCount = procCount / sizeof(DWORD);

    for (DWORD procIdx = 0; procIdx < procCount; procIdx++)
    {
        HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procList[procIdx]);
        GetProcessImageFileNameA(procHandle, processName, sizeof(processName));
        if (strstr(processName, exeName))
            TerminateProcess(procHandle, 0);
        CloseHandle(procHandle);
    }
}
