#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTimer>
#include <QDateTime>
#include "stringutil.h"
#include "QFileDialog"
#include "QMessageBox"
#include "QDebug"
#include "QImage"
#include <QFile>
#include <QTextStream>
#include <QDataStream>

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private:
    Ui::Widget *ui;

    unsigned int PlainFlag;    // SM2
    unsigned int PlainFlag2;   // Utils
    unsigned int type;
    unsigned int type2;
    QString pic_full;       // 图片名及绝对路径
    unsigned int m_pSize;   // 图片有效数据长度
    char *m_pBuff;          // 图片数据

private slots:

    void timerUpdate();

    // base64
    void base64();
    void debase64();

    // 生成公钥
    void sm2_MakePubKey();

    // 签名
    void sm2_Sign();

    // 验签
    void sm2_Verify();

    // 加密
    void sm2_Encrypt();

    // 解密
    void sm2_Decrypt();

    // 3次摘要计算
    void sm3();
    void sm3_2();
    void sm3_3();

    // 非对称加密
    void sm4_crypt();
    void sm4_decrypt();

    // 字符串处理
    void utils_Unfold();
    void utils_Fold();

    // 图片加密
    void pic_Encrypt();

    // 交易类型配置
    void sec_setType();
    void sec_setType2();

    // 身份摘要
    void sec_Digest();
    void sec_Digest_Decrypt();

    // 真实卡号摘要
    void sec_Digest2();

    // 解密敏感信息
    void sec_Inf_Encrypt();

    // 解密卡号
    void sec_Card_Decrypt();

    // 加密路由索引
    void index_Encrypt();

    // 解密口令摘要
    void index_Decrypt_PinDigest();

    // 生成6位随机数
    void Pin_Random();

    // 口令加密
    void Pin_Encrypt();

    // 口令解密
    void Pin_Decrypt();

    // 明文处理
    void sm2_PlainSet();
    void Base64PlainSet();

    // 浏览图片文件并打开
    void on_toolButton_clicked();

    // 写入图片数据到txt文档
    void writePicDataToTXT();

    // 清除
    void on_Pic_ButtonClear_clicked();
    void on_Utils_ButtonClear_clicked();
    void on_SM4_ButtonClear_clicked();
    void on_SM3_ButtonClear_clicked();
    void on_SM2_ButtonClear_clicked();
    void on_Sense_ButtonClear_clicked();
    void on_Index_ButtonClear_clicked();
    void on_Pin_ButtonClear_clicked();

};

#endif // WIDGET_H
