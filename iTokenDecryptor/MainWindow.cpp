#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QFileDialog>
#include "Ssl.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("iTokenDecryptor");
    setFixedSize(size());
    setWindowIcon(QIcon(":/icon.png"));
}
MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::getData(QString data)
{
    ui->log->clear();
    QMessageBox msg;
    QFile rsafile("private.pem");
    if (!rsafile.open(QFile::ReadOnly))
    {
        msg.setText("Failed to open RSA private key file");
        msg.exec();
        return;
    }
    QByteArray key = rsafile.readAll();
    rsafile.close();

    for (QString line : data.split('\n'))
    {
        QString str;
        if (line.startsWith("Serial:"))
        {
            ui->log->setLog(QStringList() << "\nSerial:" << line.split(':').at(1).trimmed() + "$b$d");
            continue;
        }
        else if (line.startsWith("Encrypt:"))
        {
            str = line.split(':').at(1).trimmed();
        }
        else
        {
            str = line;
        }

        if (!Ssl::decryptText(&str, key))
        {
            msg.setText(QString("Failed to decrypt : %1").arg(str));
            msg.exec();
            return;
        }
        ui->log->setLog(QStringList() << "\n" + str.split(":").at(0).trimmed() + ":" << str.mid(str.indexOf(":")+1).trimmed() + "$b$d");
    }
}

void MainWindow::on_tb_clicked()
{
    QString path = QFileDialog::getOpenFileName(this, "Open", QString(), "Sophada file (*.sophada)");
    if (path.isEmpty())
        return;
    ui->le->setText(path);
}
void MainWindow::on_bt0_clicked()
{
    QString txt = ui->te->toPlainText();
    if (txt.isEmpty())
        return;
    getData(txt);
}
void MainWindow::on_bt1_clicked()
{
    QMessageBox msg;
    QString path = ui->le->text();
    if (path.isEmpty())
        return;
    QFile file(path);
    if (!file.open(QFile::ReadOnly))
    {
        msg.setText("Failed to open token file");
        msg.exec();
        return;
    }
    QByteArray data = file.readAll();
    file.close();

    getData(QString(data));
}
