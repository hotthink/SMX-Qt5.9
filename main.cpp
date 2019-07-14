#include "widget.h"
#include <QApplication>
#include <QMessageBox>
#include <QProcess>
#include "qstring.h"
#include "QTextCodec"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QTextCodec *gbk = QTextCodec::codecForName("gb18030");

    QTextCodec::setCodecForLocale(gbk);

    Widget w;
    w.setWindowTitle("MY TOOLS");
    w.show();
    return a.exec();
}
