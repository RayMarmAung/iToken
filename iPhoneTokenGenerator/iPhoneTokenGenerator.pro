QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

DEFINES += QT_DEPRECATED_WARNINGS

INCLUDEPATH += $$PWD/Openssl

LIBS += -L$$PWD/lib -llibssl-1_1 -llibcrypto-1_1
LIBS += -lpsapi

SOURCES += \
    Log.cpp \
    Proc.cpp \
    Ssl.cpp \
    main.cpp \
    MainWindow.cpp

HEADERS += \
    Log.h \
    MainWindow.h \
    Proc.h \
    Ssl.h

FORMS += \
    MainWindow.ui

RESOURCES += \
    res.qrc

RC_FILE = iPhoneToken.rc
