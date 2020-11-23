#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "Proc.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_bt2_clicked();
    void on_bt3_clicked();

    void on_bt0_clicked();

    void on_bt1_clicked();

private:
    void searchOnStream(QByteArray data, QMultiMap<QString, QString> &map);
    void searchOnData(QByteArray data, QMultiMap<QString, QString> &map);
    void searchOnData2(QByteArray data, QMultiMap<QString, QString> &map);
    void searchDSID(QByteArray data, QMultiMap<QString, QString> &map);

    void killProcess();

private:
    Ui::MainWindow *ui;
    Proc proxy;
    QString encryptText;
};
#endif // MAINWINDOW_H
