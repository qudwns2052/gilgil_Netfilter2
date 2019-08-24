TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lnetfilter_queue
SOURCES += \
        cal_checksum.cpp \
        main.cpp \
        tcp_connection.cpp

HEADERS += \
    cal_checksum.h \
    include.h \
    protocol_structure.h \
    tcp_connection.h
