#include "widget.h"
#include "ui_widget.h"
#include "base64.h"
#include "sm2.h"
#include "sm3.h"
#include "sm4.h"
#include "stringUtil.h"
#include <random>

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget), PlainFlag(0), PlainFlag2(0), type(0), type2(0)
{
    ui->setupUi(this);

    QTimer *timer = new QTimer(this);

    connect(ui->Utils_base64_Button1, SIGNAL(clicked()), this, SLOT(base64()));
    connect(ui->Utils_base64_Button2, SIGNAL(clicked()), this, SLOT(debase64()));

    connect(ui->SM2_Button1, SIGNAL(clicked()), this, SLOT(sm2_MakePubKey()));
    connect(ui->SM2_Button2, SIGNAL(clicked()), this, SLOT(sm2_Sign()));
    connect(ui->SM2_Button3, SIGNAL(clicked()), this, SLOT(sm2_Verify()));
    connect(ui->SM2_Button_hexStr, SIGNAL(clicked()), this, SLOT(sm2_PlainSet()));
    connect(ui->SM2_Button_byteStr, SIGNAL(clicked()), this, SLOT(sm2_PlainSet()));
    connect(ui->SM2_Button4, SIGNAL(clicked()), this, SLOT(sm2_Encrypt()));
    connect(ui->SM2_Button5, SIGNAL(clicked()), this, SLOT(sm2_Decrypt()));

    connect(ui->SM3_Button1, SIGNAL(clicked()), this, SLOT(sm3()));
    connect(ui->SM3_Button2, SIGNAL(clicked()), this, SLOT(sm3_2()));
    connect(ui->SM3_Button3, SIGNAL(clicked()), this, SLOT(sm3_3()));

    connect(ui->SM4_Button1, SIGNAL(clicked()), this, SLOT(sm4_crypt()));
    connect(ui->SM4_Button2, SIGNAL(clicked()), this, SLOT(sm4_decrypt()));

    connect(ui->Utils_ButtonUnfold, SIGNAL(clicked()), this, SLOT(utils_Unfold()));
    connect(ui->Utils_ButtonFold, SIGNAL(clicked()), this, SLOT(utils_Fold()));
    connect(ui->Base64_Button_byteStr, SIGNAL(clicked()), this, SLOT(Base64PlainSet()));
    connect(ui->Base64_Button_hexStr, SIGNAL(clicked()), this, SLOT(Base64PlainSet()));

    connect(ui->Pic_Button_Encrypt, SIGNAL(clicked()), this, SLOT(pic_Encrypt()));

    connect(ui->Sec_Button1, SIGNAL(currentIndexChanged(QString)), this, SLOT(sec_setType()));
    connect(ui->Sec_Button4, SIGNAL(currentIndexChanged(QString)), this, SLOT(sec_setType2()));
    connect(ui->Sec_Button2, SIGNAL(clicked()), this, SLOT(sec_Digest()));
    connect(ui->Sec_Button2_2, SIGNAL(clicked()), this, SLOT(sec_Digest2()));
    connect(ui->Sec_Button3, SIGNAL(clicked()), this, SLOT(sec_Inf_Encrypt()));
    connect(ui->Sec_Button5, SIGNAL(clicked()), this, SLOT(sec_Card_Decrypt()));
    connect(ui->Sec_Button6, SIGNAL(clicked()), this, SLOT(sec_Digest_Decrypt()));

    connect(ui->Index_Button_Encrypt, SIGNAL(clicked()), this, SLOT(index_Encrypt()));
    connect(ui->Index_Button_PinDigest, SIGNAL(clicked()), this, SLOT(index_Decrypt_PinDigest()));

    connect(ui->Pin_Button_Random, SIGNAL(clicked()), this, SLOT(Pin_Random()));
    connect(ui->Pin_Button_Encrypt, SIGNAL(clicked()), this, SLOT(Pin_Encrypt()));
    connect(ui->Pin_Button_Decrypt, SIGNAL(clicked()), this, SLOT(Pin_Decrypt()));

    connect(ui->pushButton, SIGNAL(clicked()), this, SLOT(on_toolButton_clicked()));
    connect(ui->pushButton2, SIGNAL(clicked()), this, SLOT(writePicDataToTXT()));

    connect(ui->Pic_ButtonClear, SIGNAL(clicked()), this, SLOT(on_Pic_ButtonClear_clicked()));
    connect(ui->Utils_ButtonClear, SIGNAL(clicked()), this, SLOT(on_Utils_ButtonClear_clicked()));
    connect(ui->SM2_ButtonClear, SIGNAL(clicked()), this, SLOT(on_SM2_ButtonClear_clicked()));
    connect(ui->SM3_ButtonClear, SIGNAL(clicked()), this, SLOT(on_SM3_ButtonClear_clicked()));
    connect(ui->SM4_ButtonClear, SIGNAL(clicked()), this, SLOT(on_SM4_ButtonClear_clicked()));
    connect(ui->Sense_ButtonClear, SIGNAL(clicked()), this, SLOT(on_Sense_ButtonClear_clicked()));

    connect(timer, SIGNAL(timeout()), this, SLOT(timerUpdate()));
    timer->start(1000);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::timerUpdate()
{
    QDateTime time = QDateTime::currentDateTime();
    QString str = time.toString("yyyy-MM-dd hh:mm:ss dddd");
    ui->Time->setText(str);
}

void Widget::sm2_MakePubKey()
{
    QString Q_PriKey = ui->SM2_PriKey->text();
    std::string S_PriKey = Q_PriKey.toStdString();

    // (byte)PriKey
    std::string PriKey_byte = HexStr2BYTE(S_PriKey);
    BYTE PriKey[32];
    for (uint i = 0; i < 32; ++i)
        PriKey[i] = PriKey_byte[i];

    // 生成64字节公钥
    BYTE PubKey[64];
    EccMakeKey(PriKey, 32,PubKey, 64, 0);

    // 生成16进制公钥字符串
    std::string PubKeyString(64, '0');
    for (uint i = 0; i < 64; ++i)
        PubKeyString[i] = PubKey[i];

    std::string PubKeyHexStr = BYTE2HexStr(PubKeyString);

    ui->SM2_PubKey->setText(QString::fromStdString(PubKeyHexStr));
}

// 签名
void Widget::sm2_Sign()
{
    // 获取随机数组
    BYTE random[32];
    std::random_device rd;
    for (uint i = 0; i < 32; i++)
        random[i] = (BYTE)(rd() % 256);

    // 提取明文
    QString Q_Plain = ui->SM2_Plain->toPlainText();
    std::string S_Plain = utf8Togb18030(Q_Plain);

    // 计算摘要
    std::string hash1 = SM3::hash(S_Plain, S_Plain.size());

    QString Q_userid = ui->SM2_UserId->text();
    std::string S_userid = Q_userid.toStdString();

    QString Q_pubkey = ui->SM2_PubKey->toPlainText();
    std::string S0_pubkey = Q_pubkey.toStdString();
    std::string S_pubkey = HexStr2BYTE(S0_pubkey);

    std::string S_sm2_par_dig(128, '0');
    for (int i = 0; i < 128; i++) S_sm2_par_dig[i] = sm2_par_dig[i];

    int userid_bitlen = (S_userid.size() << 3);
    std::string s1 = "00";
    s1[0] = (BYTE) ((userid_bitlen >> 8) & 0xFF);
    s1[1] = (BYTE) (userid_bitlen & 0xFF);

    std::string s2 = s1 + S_userid + S_sm2_par_dig + S_pubkey;
    std::string hash2 = SM3::hash(s2, s2.size());

    // hash1
    std::string S_hash1 = HexStr2BYTE(hash1);

    // hash2
    std::string S_hash2 = HexStr2BYTE(hash2);

    // hash3
    std::string s3 = S_hash2 + S_hash1;
    std::string hash3 = SM3::hash(s3, s3.size());

    std::string hash3_BYTE = HexStr2BYTE(hash3);

    BYTE hash[32];

    for (uint i = 0; i < 32; i++) {
        hash[i] = hash3_BYTE[i];
    }

    // 私钥
    QString Q_PriKey = ui->SM2_PriKey->text();
    std::string S_PriKey = Q_PriKey.toStdString();
    std::string S_Prikey_BYTE = HexStr2BYTE(S_PriKey);
    BYTE PriKey[32];
    for (uint i = 0; i < 32; i++)
        PriKey[i] = S_Prikey_BYTE[i];

    // 计算签名
    BYTE sign[64];
    EccSign(hash, 32, random, 32, PriKey, 32, sign, 64);

    // base64
    std::string base64_sign = base64_encode(sign, 64);

    ui->SM2_Sign->setText(QString::fromStdString(base64_sign));
}

// 验签
void Widget::sm2_Verify()
{
    // 获取公钥
    QString Q_PubKey = ui->SM2_PubKey->toPlainText();
    std::string S_PubKey = Q_PubKey.toStdString();
    std::string S_Pubkey_BYTE = HexStr2BYTE(S_PubKey);
    BYTE PubKey[64];
    for (uint i = 0; i < 64; i++)
        PubKey[i] = S_Pubkey_BYTE[i];

    // 获取签名
    QString Q_Sign = ui->SM2_Sign->text();
    std::string S_Sign = Q_Sign.toStdString();

    std::string S_sign = base64_decode(S_Sign);

    BYTE sign[64];

    for (uint i = 0; i < 64; i++)
        sign[i] = S_sign[i];

    /* -------------digest----------- */
    // 提取明文
    QString Q_Plain = ui->SM2_Plain->toPlainText();
    std::string S_Plain = utf8Togb18030(Q_Plain);

    // 计算摘要
    std::string hash1 = SM3::hash(S_Plain, S_Plain.size());

    QString Q_userid = ui->SM2_UserId->text();
    std::string S_userid = Q_userid.toStdString();

    std::string S_sm2_par_dig(128, '0');
    for (int i = 0; i < 128; i++) S_sm2_par_dig[i] = sm2_par_dig[i];

    int userid_bitlen = (S_userid.size() << 3);
    std::string s1 = "00";
    s1[0] = (BYTE) ((userid_bitlen >> 8) & 0xFF);
    s1[1] = (BYTE) (userid_bitlen & 0xFF);

    std::string s2 = s1 + S_userid + S_sm2_par_dig + S_Pubkey_BYTE;
    std::string hash2 = SM3::hash(s2, s2.size());

    // hash1
    std::string S_hash1 = HexStr2BYTE(hash1);

    // hash2
    std::string S_hash2 = HexStr2BYTE(hash2);

    // hash3
    std::string s3 = S_hash2 + S_hash1;
    std::string hash3 = SM3::hash(s3, s3.size());

    std::string hash3_BYTE = HexStr2BYTE(hash3);

    BYTE hash[32];

    for (uint i = 0; i < 32; i++) {
        hash[i] = hash3_BYTE[i];
    }

    // 验签
    int isVerify = EccVerify(hash, 32, PubKey, 64, sign, 64);
    std::string result_Verify;

    if (isVerify == 0)
        result_Verify = "Success";
    else
        result_Verify = "Failure";

    ui->SM2_Verify->setText(QString::fromStdString(result_Verify));
}

// 公钥加密
void Widget::sm2_Encrypt()
{
    QString Q_Plain = ui->SM2_Encrypt_Text->toPlainText();
    std::string S_Plain = Q_Plain.toStdString();

    // 明文处理
    BYTE *Plain;
    uint PlainLen = 0;
    if (PlainFlag == 0) {
        PlainLen = S_Plain.size();
        Plain = new BYTE[S_Plain.size()];
        for (uint i = 0; i < PlainLen; i++)
            Plain[i] = S_Plain[i];

    }
    else {
        PlainLen = S_Plain.size() / 2;
        Plain = new BYTE[PlainLen];
        std::string S_Plain_BYTE = HexStr2BYTE(S_Plain);
        for (uint i = 0; i < PlainLen; i++)
            Plain[i] = S_Plain_BYTE[i];
    }
    
    // 获取随机数组
    BYTE random[32];
    std::random_device rd;
    for (uint i = 0; i < 32; i++)
        random[i] = (BYTE)(rd() % 256);
    
    // 获取公钥
    QString Q_PubKey = ui->SM2_PubKey->toPlainText();
    std::string S_PubKey = Q_PubKey.toStdString();
    std::string S_Pubkey_BYTE = HexStr2BYTE(S_PubKey);
    BYTE PubKey[64];
    for (uint i = 0; i < 64; i++)
        PubKey[i] = S_Pubkey_BYTE[i];
    
    // 秘文
    uint CipherLen = PlainLen + 96;
    BYTE *Cipher = new BYTE[CipherLen];
    
    // 加密
    EccEncrypt(Plain, PlainLen, random, 32, PubKey, 64, Cipher, CipherLen);

    std::string S_Cipher(CipherLen, '0');
    for (uint i = 0; i < CipherLen; i++)
        S_Cipher[i] = Cipher[i];

    // base64
    std::string result_base64 = base64_encode(reinterpret_cast<const BYTE*>
                                              (S_Cipher.c_str()), S_Cipher.length());

    ui->SM2_Decrypt_Text->setText(QString::fromStdString(result_base64));
}

// 私钥解密
void Widget::sm2_Decrypt()
{
    QString Q_Plain = ui->SM2_Decrypt_Text->toPlainText();
    std::string S_Plain = Q_Plain.toStdString();

    // base64解码
    std::string S_Plain_debase = base64_decode(S_Plain);

    // 获取秘文
    uint CipherLen = S_Plain_debase.size();
    BYTE *Cipher = new BYTE[CipherLen];
    for (uint i = 0; i < CipherLen; i++)
        Cipher[i] = S_Plain_debase[i];

    // 获取私钥
    QString Q_PriKey = ui->SM2_PriKey->text();
    std::string S_PriKey = Q_PriKey.toStdString();
    std::string S_Prikey_BYTE = HexStr2BYTE(S_PriKey);
    BYTE PriKey[32];
    for (uint i = 0; i < 32; i++)
        PriKey[i] = S_Prikey_BYTE[i];

    // 生成明文串
    uint PlainLen = CipherLen-96;
    BYTE Plain[PlainLen];

    // decrypt
    EccDecrypt(Cipher, CipherLen, PriKey, 32, Plain, PlainLen);

    std::string Plain_BYTE(PlainLen, '0');
    for (uint i = 0; i < PlainLen; i++)
        Plain_BYTE[i] = Plain[i];
    std::string ret;
    if (PlainFlag == 0) {
        ret.resize(PlainLen);
        //result = Plain_BYTE;
        for (uint i = 0; i < PlainLen; i++)
            ret[i] = Plain_BYTE[i];
    }
    else {
        ret.resize(PlainLen * 2);
        ret = BYTE2HexStr(Plain_BYTE);
    }

    ui->SM2_Encrypt_Text->setText(QString::fromStdString(ret));
}

// 1次摘要
void Widget::sm3()
{
    QString rawText = ui->SM3_RawText->toPlainText();
    std::string rawText_str = utf8Togb18030(rawText);

    std::string hash1 = SM3::hash(rawText_str, rawText_str.size());
    ui->SM3_Hash1->setText(QString::fromStdString(hash1));
}

// 2次摘要
void Widget::sm3_2()
{
    QString Q_userid = ui->SM3_UserId->text();
    std::string S_userid = Q_userid.toStdString();

    QString Q_pubkey = ui->SM3_PubKey->toPlainText();
    std::string S0_pubkey = Q_pubkey.toStdString();
    std::string S_pubkey = HexStr2BYTE(S0_pubkey);

    std::string S_sm2_par_dig(128, '0');
    for (int i = 0; i < 128; i++) S_sm2_par_dig[i] = sm2_par_dig[i];

    int userid_bitlen = (S_userid.size() << 3);
    std::string s1 = "00";
    s1[0] = (BYTE) ((userid_bitlen >> 8) & 0xFF);
    s1[1] = (BYTE) (userid_bitlen & 0xFF);

    std::string s2 = s1 + S_userid + S_sm2_par_dig + S_pubkey;

    std::string hash2 = SM3::hash(s2, s2.size());

    ui->SM3_Hash2->setText(QString::fromStdString(hash2));
}

// 3次摘要
void Widget::sm3_3()
{
    // hash1
    QString Q_hash1 = ui->SM3_Hash1->text();
    std::string S0_hash1 = Q_hash1.toStdString();
    std::string S_hash1 = HexStr2BYTE(S0_hash1);

    // hash2
    QString Q_hash2 = ui->SM3_Hash2->text();
    std::string S0_hash2 = Q_hash2.toStdString();
    std::string S_hash2 = HexStr2BYTE(S0_hash2);

    // hash3
    std::string s3 = S_hash2 + S_hash1;
    std::string hash3 = SM3::hash(s3, s3.size());

    ui->SM3_Hash3->setText(QString::fromStdString(hash3));
}

void Widget::sm4_crypt()
{
    // 随机对称密钥
    QString Q_key = ui->SM4_Key->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 明文
    QString Q_RawText = ui->SM4_RawText->toPlainText();
    std::string S_RawText = utf8Togb18030(Q_RawText);
    const uint rawl = S_RawText.size();
    BYTE input[rawl] = { 0 };
    for (uint i = 0; i < rawl; i++) input[i] = S_RawText[i];
    const unsigned int n = (rawl / 16 + 1) * 16;
    BYTE input2[n] = { 0 };
    BYTE output[n] = { 0 };

    // PKCS#7填充处理
    pkcs7(input, rawl, n, input2);

    //encrypt standard testing vector
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;

    BYTE iv[16] = { 0 };
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_cbc(&ctx, 1, n, iv, input2, output);

    std::string secText(n, '0');
    for (uint i = 0; i < n; i++) secText[i] = output[i];

    // base64
    std::string Str = base64_encode(reinterpret_cast<const BYTE*>
                                    (secText.c_str()), secText.length());

    ui->SM4_SecText->setText(QString::fromStdString(Str));
}

void Widget::sm4_decrypt()
{
    // 随机对称密钥
    QString Q_key = ui->SM4_Key->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 秘文(base64)
    QString Q_SecText = ui->SM4_SecText->toPlainText();
    std::string S_SecText = Q_SecText.toStdString();

    // debase64
    std::string S_SecText_debase = base64_decode(S_SecText);
    const uint n = S_SecText_debase.size();
    BYTE input[n] = { 0 };
    BYTE output[n] = { 0 };
    for (uint i = 0; i < n; i++) input[i] = S_SecText_debase[i];

    // decrypt
    BYTE iv[16] = { 0 };
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_cbc(&ctx, 0, n, iv, input, output);

    // 计算填充字节数
    uint l = n - output[n-1];
    std::string ret(l, '0');

    for (uint i = 0; i < l; i++) ret[i] = output[i];

    ui->SM4_RawText->setText(QString::fromStdString(ret));
}

void Widget::utils_Unfold()
{
    QString Q_byteStr = ui->Utils_byteStr->toPlainText();
    std::string S_byteStr = utf8Togb18030(Q_byteStr);

    std::string S_hexStr = BYTE2HexStr(S_byteStr);

    ui->Utils_hexStr->setText(QString::fromStdString(S_hexStr));
}

void Widget::utils_Fold()
{
    QString Q_hexStr = ui->Utils_hexStr->toPlainText();
    std::string S_hexStr = utf8Togb18030(Q_hexStr);

    std::string S_byteStr = HexStr2BYTE(S_hexStr);

    ui->Utils_byteStr->setText(QString::fromStdString(S_byteStr));
}

void Widget::base64()
{
    QString RawText = ui->Utils_base64_plain->toPlainText();
    std::string RawText_str = utf8Togb18030(RawText);

    // hexStr
    if (PlainFlag2 == 1)  {
        std::string str = HexStr2BYTE(RawText_str);
        std::string SecStr = base64_encode(reinterpret_cast<const unsigned char*>
                                           (str.c_str()), str.length());
        ui->Utils_base64_cipher->setText(QString::fromStdString(SecStr));
        return;
    }
    // byteStr
    std::string SecStr = base64_encode(reinterpret_cast<const unsigned char*>
                                       (RawText_str.c_str()), RawText_str.length());
    ui->Utils_base64_cipher->setText(QString::fromStdString(SecStr));
}

void Widget::debase64()
{
    QString SecText = ui->Utils_base64_cipher->toPlainText();
    std::string debase64 = base64_decode(SecText.toStdString());

    // hexStr
    if (PlainFlag2 == 1) {
        std::string str = BYTE2HexStr(debase64);
        ui->Utils_base64_plain->setText(QString::fromStdString(str));
        return;
    }
    // byteStr
    ui->Utils_base64_plain->setText(QString::fromStdString(debase64));
}

void Widget::pic_Encrypt()
{ 
    // 获取图片随机对称密钥
    QString Q_key = ui->Pic_Key->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = (unsigned char)S_key[i];

    // Read a pic file
    QFile file(pic_full);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::information(NULL, tr("Warning"), tr("Open failed."));
        return;
    }

    //内存分配
    int nSize = file.size();
    m_pBuff = new char[nSize + 1];

    QDataStream in(&file);
    //需要的有效长度为函数返回值，并非nSize
    m_pSize = in.readRawData(m_pBuff, nSize);

    const unsigned int n = (m_pSize / 16 + 1) * 16;
    unsigned char input2[n] = { 0 };
    unsigned char output[n] = { 0 };

    // PKCS#7填充处理
    pkcs7_2(m_pBuff, m_pSize, n, input2);

    //encrypt standard testing vector
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;

    BYTE iv[16] = { 0 };
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_cbc(&ctx, 1, n, iv, input2, output);

    std::string secText(n, '0');
    for (uint i = 0; i < n; i++) secText[i] = output[i];

    // base64
    std::string Str = base64_encode(reinterpret_cast<const BYTE*>
                                    (secText.c_str()), secText.length());

    ui->Pic_Cipher->setText(QString::fromStdString(Str));

    // Release memory
    if (m_pBuff != nullptr) {
        delete m_pBuff;
        m_pBuff = nullptr;
    }
}

// 交易类型设置
void Widget::sec_setType()
{
    if (ui->Sec_Button1->currentIndex() == 3)
        type = 1;
    else
        type = 0;
}

void Widget::sec_setType2()
{
    if (ui->Sec_Button4->currentIndex() == 3)
        type2 = 1;
    else
        type2 = 0;
}

// 身份摘要计算
void Widget::sec_Digest()
{
    /* ----姓名---- */
    QString Q_Name = ui->Sec_Name->text();
    std::string Name = utf8Togb18030(Q_Name.toUpper());

    /* ----身份证---- */
    QString Q_Id = ui->Sec_Id->text();
    QString id = Q_Id.toUpper();
    std::string Id = id.toStdString();

    // 身份信息合成
    BYTE idInf[50];
    for (uint i = 0; i < 50; i++) idInf[i] = ' ';

    for (uint i = 0; i < Name.size(); i++)
        idInf[i] = Name[i];
    for (uint i = 0; i < Id.size(); i++)
        idInf[i+30] = Id[i];

    std::string S_idInf(50, '0');
    for (uint i = 0; i < 50; i++)
        S_idInf[i] = idInf[i];

    // 计算身份信息摘要
    std::string IdDigest = SM3::hash(S_idInf, S_idInf.size());

    ui->Sec_Digest->setText(QString::fromStdString(IdDigest));
}

// 真实卡号摘要计算
void Widget::sec_Digest2()
{
    /* ----姓名---- */
    QString Q_Name = ui->Sec_Name->text();
    std::string Name = utf8Togb18030(Q_Name.toUpper());

    /* ----卡号---- */
    QString Q_Card = ui->Sec_Card->text();
    std::string Card = Q_Card.toStdString();

    // 真实卡号合成
    BYTE idInf[49];
    for (uint i = 0; i < 49; i++) idInf[i] = ' ';

    for (uint i = 0; i < Card.size(); i++)
        idInf[i] = Card[i];
    for (uint i = 0; i < Name.size(); i++)
        idInf[i+19] = Name[i];

    std::string S_idInf(49, '0');
    for (uint i = 0; i < 49; i++)
        S_idInf[i] = idInf[i];

    // 计算身份信息摘要
    std::string CardDigest = SM3::hash(S_idInf, S_idInf.size());

    ui->Sec_Digest->setText(QString::fromStdString(CardDigest));
}

// 加密敏感信息
void Widget::sec_Inf_Encrypt()
{
    /* -----计算身份信息摘要----- */

    /* ----姓名---- */
    QString Q_Name = ui->Sec_Name->text();
    std::string Name = utf8Togb18030(Q_Name.toUpper());

    /* ----身份证---- */
    QString Q_Id = ui->Sec_Id->text();
    QString id = Q_Id.toUpper();
    std::string Id = id.toStdString();

    // 身份信息合成
    BYTE idInf[50];
    for (uint i = 0; i < 50; i++) idInf[i] = ' ';

    for (uint i = 0; i < Name.size(); i++)
        idInf[i] = Name[i];
    for (uint i = 0; i < Id.size(); i++)
        idInf[i+30] = Id[i];

    std::string S_idInf(50, '0');
    for (uint i = 0; i < 50; i++)
        S_idInf[i] = idInf[i];

    // 计算身份信息摘要
    std::string IdDigest = SM3::hash(S_idInf, S_idInf.size());
    std::string Digest = HexStr2BYTE(IdDigest);

    // 获取敏感信息对称密钥
    QString Q_Sk = ui->Sec_Sk1->text();
    std::string S_Sk = Q_Sk.toStdString();
    std::string S_Sk_BYTE = HexStr2BYTE(S_Sk);
    BYTE key[16];
    for (uint i = 0; i < 16; i++)
        key[i] = S_Sk_BYTE[i];

    // 获取卡号
    QString Q_Card = ui->Sec_Card->text();
    std::string Card = Q_Card.toStdString();

    // 根据交易类型计算组合combo
    std::string combo;
    if (type == 1)
        combo = Digest;
    else
        combo = Card + "," + Digest;

    const uint rawl = combo.size();
    const unsigned int n = (rawl / 16 + 1) * 16;
    BYTE input2[n] = { 0 };
    BYTE output[n] = { 0 };

    // PKCS#7填充处理
    pkcs7(reinterpret_cast<const BYTE*>
          (combo.c_str()), rawl, n, input2);

    //encrypt standard testing vector
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;

    BYTE iv[16] = { 0 };
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_cbc(&ctx, 1, n, iv, input2, output);

    std::string secText(n, '0');
    for (uint i = 0; i < n; i++) secText[i] = output[i];

    // base64
    std::string Str = base64_encode(reinterpret_cast<const BYTE*>
                                    (secText.c_str()), secText.length());

    ui->Sec_EncryptText->setText(QString::fromStdString(Str));
}

// 解密身份摘要
void Widget::sec_Digest_Decrypt()
{
    // 随机对称密钥
    QString Q_key = ui->Sec_Sk2->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 秘文(base64)
    QString Q_SecText = ui->Sec_Cipher->toPlainText();
    std::string S_SecText = utf8Togb18030(Q_SecText);

    // debase64
    std::string S_SecText_debase = base64_decode(S_SecText);

    const uint n = S_SecText_debase.size();
    BYTE input[n] = { 0 };
    BYTE output[n] = { 0 };
    for (uint i = 0; i < n; i++) input[i] = S_SecText_debase[i];

    // decrypt
    BYTE iv[16] = { 0 };
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_cbc(&ctx, 0, n, iv, input, output);

    // 去掉填充字节
    uint l = n - output[n-1];
    std::string ret(l, '0');

    for (uint i = 0; i < l; i++) ret[i] = output[i];

    std::string DigestBYTE(32, '0');

    if (type2 == 1)
        DigestBYTE = ret;
    else {
        int j = 31;
        for (uint i = ret.size() - 1; i > ret.size() - 1 - 32; i--)
            DigestBYTE[j--] = ret[i];
    }

    std::string digest = BYTE2HexStr(DigestBYTE);

    ui->Sec_Digest_2->setText(QString::fromStdString(digest));
}

// 解密卡号
void Widget::sec_Card_Decrypt()
{
    if (type == 1)
        return;

    // 随机对称密钥
    QString Q_key = ui->Sec_Sk2->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 秘文(base64)
    QString Q_SecText = ui->Sec_Cipher->toPlainText();
    std::string S_SecText = utf8Togb18030(Q_SecText);

    // debase64
    std::string S_SecText_debase = base64_decode(S_SecText);

    const uint n = S_SecText_debase.size();
    BYTE input[n] = { 0 };
    BYTE output[n] = { 0 };
    for (uint i = 0; i < n; i++) input[i] = S_SecText_debase[i];

    // decrypt
    BYTE iv[16] = { 0 };
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_cbc(&ctx, 0, n, iv, input, output);

    // 去掉填充字节
    uint l = n - output[n-1];
    std::string ret(l, '0');

    for (uint i = 0; i < l; i++) ret[i] = output[i];

    // 提取卡号
    std::string card(l-32-1, '0');
    for (uint i = 0; i < l - 33; i++)
        card[i] = ret[i];

    ui->Sec_Card_2->setText(QString::fromStdString(card));
}

// 加密路由索引
void Widget::index_Encrypt()
{
    // 随机对称密钥
    QString Q_key = ui->Index_Key->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 时间戳
    QString Q_TimeStamp = ui->Index_TimeStamp->text();
    std::string TimeStamp = Q_TimeStamp.toStdString();
    TimeStamp = "000000000000000000" + TimeStamp;

    // 口令摘要
    QString pin = ui->Index_Pin->text();
    std::string Spin = pin.toStdString();

    std::string hash_pin_hexstr = SM3::hash(Spin, Spin.size());
    std::string hash_pin = HexStr2BYTE(hash_pin_hexstr);

    // 异或
    BYTE xorRlt[32];
    for (uint i = 0; i < 32; i++)
        xorRlt[i] = (BYTE)(TimeStamp[i] ^ hash_pin[i]);

    // SM4加密
    BYTE output[32];

    //encrypt standard testing vector
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;

    BYTE iv[16] = { 0 };
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_cbc(&ctx, 1, 32, iv, xorRlt, output);

    std::string secText(32, '0');
    for (uint i = 0; i < 32; i++) secText[i] = output[i];

    // base64
    std::string Str = base64_encode(reinterpret_cast<const BYTE*>
                                    (secText.c_str()), secText.length());

    ui->Index_Encrypt->setText(QString::fromStdString(Str));
}

// 解密口令摘要
void Widget::index_Decrypt_PinDigest()
{
    // 随机对称密钥
    QString Q_key = ui->Index_Key2->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 提取秘文
    QString Q_Cipher = ui->Index_Cipher->toPlainText();
    std::string S_Cipher = Q_Cipher.toStdString();

    // debase64
    std::string S_Cipher_debase = base64_decode(S_Cipher);

    BYTE input[32] = { 0 };
    BYTE output[32] = { 0 };
    for (uint i = 0; i < 32; i++) input[i] = S_Cipher_debase[i];

    // decrypt
    BYTE iv[16] = { 0 };
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_cbc(&ctx, 0, 32, iv, input, output);

    // 获取时间戳
    QString Q_timeStamp = ui->Index_TimeStamp2->text();
    std::string timeStamp = Q_timeStamp.toStdString();
    timeStamp = "000000000000000000" + timeStamp;

    // 计算口令摘要
    std::string pinDigest(32, '0');
    for (uint i = 0; i < 32; i++)
        pinDigest[i] = (BYTE)(timeStamp[i] ^ output[i]);

    std::string ret = BYTE2HexStr(pinDigest);

    ui->Index_decrypt_pinDigest->setText(QString::fromStdString(ret));
}

// 生成6位随机数
void Widget::Pin_Random()
{
    srand( (unsigned)time( NULL ) );
    std::string rd(6, '0');
    for (uint i = 0; i < 6; i++)
        rd[i] = (BYTE)(rand() % 10 + 48);

    ui->Pin_Random->setText(QString::fromStdString(rd));
}

// 口令加密
void Widget::Pin_Encrypt()
{
    // 随机对称密钥
    QString Q_key = ui->Pin_Key->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 随机数
    QString Q_rd = ui->Pin_Random->text();
    std::string rd = Q_rd.toStdString();

    // 时间戳
    QString Q_timeStamp = ui->Pin_TimeStamp->text();
    std::string timeStamp = Q_timeStamp.toStdString();
    std::string xor_salt = timeStamp + rd;

    // 按照卡号要求进行截取
    std::string Spanblock =
            HexStr2BYTE("00000000000000000000" + xor_salt.substr(xor_salt.size()-1-12, xor_salt.size()-1));

    // 计算panBlock
    BYTE panBlock[16];
    for (uint i = 0; i < 16; i++)
        panBlock[i] = Spanblock[i];

    // Pin
    QString Q_pin = ui->Pin_Pin->text();
    std::string pin = Q_pin.toStdString();

    // 计算pinBlock
    std::string Spinblock = HexStr2BYTE("06" + pin + "FFFFFFFFFFFFFFFFFFFFFFFF");

    BYTE pinBlock[16];
    for (uint i = 0; i < 16; i++)
        pinBlock[i] = Spinblock[i];

    // xor
    BYTE _xor[16];
    for (uint i = 0; i < 16; i++)
        _xor[i] = (BYTE)(panBlock[i] ^ pinBlock[i]);

    // SM4
    BYTE output[16];

    //encrypt standard testing vector
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;

    BYTE iv[16] = { 0 };
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_cbc(&ctx, 1, 16, iv, _xor, output);

    std::string cipher(16, '0');
    for (uint i = 0; i < 16; i++) cipher[i] = output[i];

    // base64
    std::string Str = base64_encode(reinterpret_cast<const BYTE*>
                                    (cipher.c_str()), cipher.length());

    ui->Pin_Encrypt->setText(QString::fromStdString(Str));

}

// 口令解密
void Widget::Pin_Decrypt()
{
    // 随机对称密钥
    QString Q_key = ui->Pin_Key2->text();
    std::string S0_key = Q_key.toStdString();
    std::string S_key = HexStr2BYTE(S0_key);
    BYTE key[16] = { 0 };
    for (int i = 0; i < 16; i++) key[i] = S_key[i];

    // 秘文
    QString Q_Cipher = ui->Pin_Cipher->toPlainText();
    std::string S_Cipher = Q_Cipher.toStdString();

    // debase64
    std::string S_Cipher_debase = base64_decode(S_Cipher);

    BYTE input[16] = { 0 };
    BYTE output[16] = { 0 };
    for (uint i = 0; i < 16; i++) input[i] = S_Cipher_debase[i];

    // decrypt
    BYTE iv[16] = { 0 };
    sm4_context ctx;
    ctx.mode = 0;
    for (uint i = 0; i < 32; i++) ctx.sk[i] = 0;
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_cbc(&ctx, 0, 16, iv, input, output);

    // 获取秘文时间戳
    QString Q_timeStamp = ui->Pin_TimeStamp2->text();
    std::string timeStamp = Q_timeStamp.toStdString();

    // 获取秘文6位随机数
    QString Q_rd = ui->Pin_Random_2->text();
    std::string rd = timeStamp + Q_rd.toStdString();

    // 获取panBlock
    std::string SpanBlock = "00000000000000000000" + rd.substr(rd.size()-1-12, rd.size()-1);
    std::string panBlock = HexStr2BYTE(SpanBlock);

    // 计算pinBlock
    std::string pinBlock(16, '0');
    for (uint i = 0; i < 16; i++)
        pinBlock[i] = (BYTE)(output[i] ^ panBlock[i]);

    // 获取pin
    std::string pin = (BYTE2HexStr(pinBlock)).substr(2, 6);

    ui->Pin_Pin2->setText(QString::fromStdString(pin));
}

// 明文处理
void Widget::sm2_PlainSet()
{
    if (ui->SM2_Button_byteStr->isChecked())
        PlainFlag = 0;
    else
        PlainFlag = 1;
}

// 明文处理
void Widget::Base64PlainSet()
{
    if (ui->Base64_Button_byteStr->isChecked())
        PlainFlag2 = 0;
    else
        PlainFlag2 = 1;
}

// 清屏
void Widget::on_Pic_ButtonClear_clicked()
{
    ui->Pic_Key->clear();
    ui->Pic_Cipher->clear();
    ui->label->clear();
    ui->Pic_Name->clear();
    ui->Pic_txt->clear();
}

void Widget::on_Utils_ButtonClear_clicked()
{
    ui->Utils_base64_plain->clear();
    ui->Utils_base64_cipher->clear();
    ui->Utils_byteStr->clear();
    ui->Utils_hexStr->clear();
}

void Widget::on_SM4_ButtonClear_clicked()
{
    ui->SM4_Key->clear();
    ui->SM4_RawText->clear();
    ui->SM4_SecText->clear();
}

void Widget::on_SM3_ButtonClear_clicked()
{
    ui->SM3_Hash1->clear();
    ui->SM3_Hash2->clear();
    ui->SM3_Hash3->clear();
    ui->SM3_PubKey->clear();
    ui->SM3_RawText->clear();
    ui->SM3_UserId->clear();
}

void Widget::on_SM2_ButtonClear_clicked()
{
    ui->SM2_Decrypt_Text->clear();
    ui->SM2_Encrypt_Text->clear();
    ui->SM2_Plain->clear();
    ui->SM2_PriKey->clear();
    ui->SM2_PubKey->clear();
    ui->SM2_Sign->clear();
    ui->SM2_UserId->clear();
    ui->SM2_Verify->clear();
}

void Widget::on_Sense_ButtonClear_clicked()
{
    ui->Sec_Card->clear();
    ui->Sec_Card_2->clear();
    ui->Sec_Cipher->clear();
    ui->Sec_Digest->clear();
    ui->Sec_Digest_2->clear();
    ui->Sec_EncryptText->clear();
    ui->Sec_Id->clear();
    ui->Sec_Name->clear();
    ui->Sec_Sk1->clear();
    ui->Sec_Sk2->clear();
}

void Widget::on_Index_ButtonClear_clicked()
{
    ui->Index_Cipher->clear();
    ui->Index_decrypt_pinDigest->clear();
    ui->Index_Encrypt->clear();
    ui->Index_Key->clear();
    ui->Index_Key2->clear();
    ui->Index_Pin->clear();
    ui->Index_TimeStamp->clear();
    ui->Index_TimeStamp2->clear();
}

void Widget::on_Pin_ButtonClear_clicked()
{
    ui->Pin_Cipher->clear();
    ui->Pin_Encrypt->clear();
    ui->Pin_Key->clear();
    ui->Pin_Key2->clear();
    ui->Pin_Random->clear();
    ui->Pin_Random_2->clear();
    ui->Pin_TimeStamp->clear();
    ui->Pin_TimeStamp2->clear();
    ui->Pin_Pin2->clear();
    ui->Pin_Pin->clear();
}

void Widget::on_toolButton_clicked()
{
    QString file_full, file_name, file_path;
    QFileInfo fi;

    pic_full = QFileDialog::getOpenFileName(
                this,
                tr("open a picture"),
                QDir::currentPath(),
                //"C:/",
                tr("images(*.png *.jpg *.jpeg *.bmp)"));

    fi = QFileInfo(pic_full);
    file_name = fi.fileName();
    file_path = fi.absolutePath();

    // 显示选择的图片名
    ui->Pic_Name->setText(file_name);

    // 显示图片
    QPixmap *pixmap = new QPixmap(pic_full);
    pixmap->scaled(ui->label->size(), Qt::KeepAspectRatio);
    ui->label->setScaledContents(true);
    ui->label->setPixmap(*pixmap);
}

void Widget::writePicDataToTXT()
{
    // browse & read data of this picture
    QFile file(pic_full);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::information(NULL, tr("Warning"), tr("Open failed."));
        return;
    }

    // 内存分配
    int nSize = file.size();
    m_pBuff = new char[nSize + 1];

    QDataStream in(&file);
    //需要的有效长度为函数返回值，并非nSize
    m_pSize = in.readRawData(m_pBuff, nSize);

    // base64
    std::string img = base64_encode_pic(m_pBuff, m_pSize);

    QString curPath = QDir::currentPath() + "/" + "pic_base64.txt";

    // write data of the picture to the txt
    QFile data(curPath);

    if (!data.open(QFile::WriteOnly | QFile::Text))
    {
        QMessageBox::information(this, "Error Message", "Please Select a Text File!");
        return;
    }
    QTextStream out(&data);
    out << img.c_str();
    data.flush();
    data.close();

    ui->Pic_txt->setText(curPath);

    if (m_pBuff != nullptr) {
        delete m_pBuff;
        m_pBuff = nullptr;
    }
}
