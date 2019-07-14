#ifndef STRINGUTIL_H
#define STRINGUTIL_H

#include <string>
#include <QTextCodec>
#include <QByteArray>

typedef unsigned char BYTE;
typedef unsigned int Word;

const static BYTE lett16[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

std::string BYTE2HexStr(const std::string &src);

std::string HexStr2BYTE(const std::string &src);

std::string Word2String(Word *src);

void pkcs7(const unsigned char *input, const unsigned int len, const unsigned int n, unsigned char *output);
void pkcs7_2(char *input, const unsigned int len, const unsigned int n, unsigned char *output);

std::string sblank(const unsigned int &n);

std::string utf8Togb18030(const QString& qstr);

#endif // STRINGUTIL_H
