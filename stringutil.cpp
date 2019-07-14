#include <string>
#include "stringUtil.h"

std::string BYTE2HexStr(const std::string &src)
{
    unsigned int l = src.size();
    std::string ret(l * 2, '0');
    for (unsigned int i = 0; i < l; i++) {
        ret[i * 2] = lett16[(unsigned char)src[i] / 16];
        ret[i * 2 + 1] = lett16[(unsigned char)src[i] % 16];
    }
    return ret;
}

std::string HexStr2BYTE(const std::string &src)
{
    std::string ret(src.size() / 2, '0');
    unsigned int le16[70 + 1] = { 0 };
    for (int i = 48; i < 58; i++)
        le16[i] = i - 48;
    le16['A'] = 10; le16['B'] = 11;
    le16['C'] = 12; le16['D'] = 13;
    le16['E'] = 14; le16['F'] = 15;

    for (unsigned int i = 0; i * 2 < src.size(); i++) {
        ret[i] = (BYTE)(le16[(unsigned int)src[i * 2]] * 16 + le16[(unsigned int)src[i * 2 + 1]]);
    }
    return ret;
}

std::string int2Hexstr(const int &a) {
    std::string ret(2, '0');
    ret[0] = lett16[a / 16];
    ret[1] = lett16[a % 16];

    return ret;
}

std::string Word2String(Word *src)
{
    std::string ret;
    BYTE a = '0', b = '0', c = '0', d = '0';
    std::string s_a; std::string s_b;
    std::string s_c; std::string s_d;

    for (int i = 0; i < 8; i++) {

        a = (BYTE)(src[i] & 0xFF);
        s_a = int2Hexstr((int)a);

        b = (BYTE)((src[i] >> 8) & 0xFF);
        s_b = int2Hexstr((int)b);

        c = (BYTE)((src[i] >> 16) & 0xFF);
        s_c = int2Hexstr((int)c);

        d = (BYTE)((src[i] >> 24) & 0xFF);
        s_d = int2Hexstr((int)d);

        ret += s_d + s_c + s_b + s_a;
    }

    return ret;
}

void pkcs7(const unsigned char *input, const unsigned int len, const unsigned int n, unsigned char *output)
{
    unsigned int l = n - len;
    for (unsigned int i = 0; i < len; i++)
        output[i] = input[i];
    for (unsigned int i = 0; i < l; i++) {
        output[i + len] = l;
    }
}

void pkcs7_2(char *input, const unsigned int len, const unsigned int n, unsigned char *output)
{
    unsigned int l = n - len;
    for (unsigned int i = 0; i < len; i++)
        output[i] = (unsigned char)input[i];
    for (unsigned int i = 0; i < l; i++) {
        output[i + len] = l;
    }
}

std::string sblank(const unsigned int &n)
{
    std::string res = "";
    for (unsigned int i = 0; i < n; ++i)
        res += " ";
    return res;
}

std::string utf8Togb18030(const QString& qstr)
{
    QTextCodec* pCodec = QTextCodec::codecForName("gb18030");
    if(!pCodec) return "";
    QByteArray ar = pCodec->fromUnicode(qstr);
    std::string cstr = ar.data();
    return cstr;
}


