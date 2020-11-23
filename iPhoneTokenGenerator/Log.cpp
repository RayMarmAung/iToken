#include "Log.h"

LogWgt::LogWgt(QWidget *parent)
    : QTextBrowser(parent)
{
    this->setObjectName("LogWgt");
    this->setReadOnly(true);
    //this->setFocusPolicy(Qt::NoFocus);
    this->setOverwriteMode(true);
    this->setOpenExternalLinks(false);
    this->setOpenLinks(false);
    this->setLineWrapMode(QTextEdit::NoWrap);
    this->setViewportMargins(10, 10, 10, 10);
    this->viewport()->setAutoFillBackground(false);

    connect(this, SIGNAL(anchorClicked(QUrl)), SLOT(setOpenLink(QUrl)));
}
LogWgt::~LogWgt()
{
    this->deleteLater();
}

void LogWgt::setTitle(QString txt)
{
    this->clear();

    QBrush operationColor(Qt::black);
    QBrush titleColor(Qt::blue);

    QTextCursor cursor(this->textCursor());
    QTextCharFormat format1;
    {
        format1.setForeground(operationColor);
        format1.setFontWeight(QFont::Bold);
    }
    QTextCharFormat format2;
    {
        format2.setForeground(titleColor);
        format2.setFontWeight(QFont::Bold);
    }

    cursor.insertText("OPERATION: ", format1);
    cursor.insertText(txt.toUpper() + "\n", format2);
    cursor.movePosition(QTextCursor::End);
}
void LogWgt::setLine()
{
    QTextCursor cursor(this->textCursor());
    {
        cursor.movePosition(QTextCursor::End);
        cursor.insertText("\n");
        cursor.movePosition(QTextCursor::End);
    }
    QScrollBar *scroll = this->verticalScrollBar();
    {
        scroll->setValue(scroll->maximum());
    }
}
void LogWgt::setLog(QStringList list, bool need_dot)
{
    QTextCursor cursor(this->textCursor());
    cursor.movePosition(QTextCursor::End);

    for (int j = 0; j < list.count(); j++)
    {
        bool with_space = true;
        QString line = list.at(j);
        QStringList attrs = line.split('$', QString::SkipEmptyParts);
        QTextCharFormat format;
        format.setForeground(Qt::black);

        if (attrs.count() > 1)
        {
            for (int i = 1; i < attrs.count(); i++)
            {
                QString attr = attrs.at(i);

                if (attr == "b")
                    format.setFontWeight(QFont::Bold);
                else if (attr == "i")
                    format.setFontItalic(true);
                else if (attr == "l")
                {
                    format.setForeground(Qt::blue);
                    //format.setForeground(QBrush(QColor(this->colorMap.value("title", "#0a64ff"))));
                    format.setAnchor(true);
                    format.setUnderlineStyle(QTextCharFormat::SingleUnderline);
                    format.setAnchorHref(attrs.at(0));
                    format.setAnchorNames(QStringList() << attrs.at(0));
                }
                else if (attr == "n")
                    with_space = false;
                else if (attr == "d")
                    need_dot = false;
                else if (attr.startsWith("c"))
                {
                    format.setForeground(Qt::blue);
                }
            }
        }

        cursor.insertText(attrs.at(0), format);
        if (j < (list.count() - 1))
        {
            if (with_space)
                cursor.insertText(" ", format);
        }
    }
    if (need_dot)
    {
        QTextCharFormat format;
        format.setForeground(Qt::black);
        cursor.insertText("... ", format);
    }

    cursor.movePosition(QTextCursor::End);
    this->verticalScrollBar()->setValue(this->verticalScrollBar()->maximum());
}
void LogWgt::setState(int state, QString warning)
{
    switch (state)
    {
    case 0: this->setLog(QStringList() << "DONE$b$n$cokay", false); break;
    case 1: this->setLog(QStringList() << "FAILED$b$n$cfail", false); break;
    case 2: this->setLog(QStringList() << "SKIPPED$b$n$cskip", false); break;
    default: break;
    }

    if (!warning.isEmpty())
        this->setLog(QStringList() << QString(" (%1)$b$cwarn").arg(warning.toUpper()), false);
}
void LogWgt::setInfor(QString txt, QByteArray &data)
{
    if (data.isEmpty())
        return;

    QTextStream stream(&data);
    {
        if (!txt.isEmpty())
            this->setLog(QStringList() << QString("\n\n%1\n$b").arg(txt.toUpper()), false);

        while (!stream.atEnd())
        {
            QString line = stream.readLine();
            if (!line.contains(":"))
                continue;
            QString key = QString(line.split(':').at(0)).trimmed();
            QString val = line.split(':').at(1);
            if (val.isEmpty())
                continue;

            this->setLog(QStringList() << QString("\n ● %1:").arg(key) << QString("%1$b").arg(val), false);
        }
    }
}
void LogWgt::setInfor(QMultiMap<QString, QString> data)
{
    if (data.isEmpty())
        return;
    this->setLog(QStringList() << "\n", false);
    for (QMultiMap<QString, QString>::iterator it = data.begin(); it != data.end(); it++)
        this->setLog(QStringList() << QString("\n ● %1:").arg(it.key()) << QString("%1$b").arg(it.value()), false);
}
void LogWgt::setOpenLink(QUrl url)
{
    if (url.toString().contains("http"))
        QDesktopServices::openUrl(url);
    else
        QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(url.toString()).absolutePath()));
}
