!equals(QT_MAJOR_VERSION, 5) {
	error("Requires Qt5")
}

TEMPLATE = app

CONFIG -= app_bundle
CONFIG += sdk_no_version_check

TARGET = generate_network_key
INCLUDEPATH += .
SOURCES += generate_network_key.cpp
