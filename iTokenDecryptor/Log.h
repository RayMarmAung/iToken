#ifndef LOG_H
#define LOG_H

#include <QtWidgets>
#include <QObject>
#include <QtCore>

class LogWgt : public QTextBrowser
{
    Q_OBJECT
public:
    explicit LogWgt(QWidget *parent = 0);
    ~LogWgt();

public slots:
    void setTitle(QString txt);
    void setLine();
    void setLog(QStringList list, bool need_dot = true);
    void setState(int state = 0, QString warning = QString());
    void setInfor(QString txt, QByteArray &data);
    void setInfor(QMultiMap<QString, QString> data);

private slots:
    void setOpenLink(QUrl url);

private:
    QString curTheme;
    QHash<QString, QString> colorMap;
};

#endif // LOG_H
