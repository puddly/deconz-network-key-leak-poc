#include <QTextStream>
#include <QDateTime>
#include <QtGlobal>

int main() {
	qint64 seed = QDateTime::currentMSecsSinceEpoch();
	qsrand(seed);

	QTextStream(stdout) << "Seed: " << seed << "\n\n";

	quint32 initial = qrand();
	QTextStream(stdout) << "Initial output: " << initial << "\n\n";

	quint16 panId = initial;
	QTextStream(stdout) << "panId: " << panId << "\n\n";

	QByteArray nwkKey1 = QByteArray::number(qrand(), 16);
	QByteArray nwkKey2 = QByteArray::number(qrand(), 16);
	QByteArray nwkKey3 = QByteArray::number(qrand(), 16);
	QByteArray nwkKey4 = QByteArray::number(qrand(), 16);

	QTextStream(stdout) << "nwkKey1: " << nwkKey1 << "\n";
	QTextStream(stdout) << "nwkKey2: " << nwkKey2 << "\n";
	QTextStream(stdout) << "nwkKey3: " << nwkKey3 << "\n";
	QTextStream(stdout) << "nwkKey4: " << nwkKey4 << "\n\n";

	QByteArray nwkKey = nwkKey1.append(nwkKey2).append(nwkKey3).append(nwkKey4);
	nwkKey.resize(16);

	QTextStream(stdout) << nwkKey.toHex() << "\n";

	return 0;
}
