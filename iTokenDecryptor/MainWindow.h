#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

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
    void on_tb_clicked();
    void on_bt0_clicked();

    void on_bt1_clicked();

private:
    void getData(QString path);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
