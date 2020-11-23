#ifndef SSL_H
#define SSL_H

#include <QtCore>

class Ssl : public QObject
{
public:
    explicit Ssl(QObject *parent = 0):
        QObject(parent) {}
    ~Ssl() {}

    static bool generateKeyPair(QString output);
    static bool encryptText(QString *text, QByteArray rsa_key, bool base64_encode = true);
    static bool decryptText(QString *text, QByteArray rsa_key, bool base64_decode = true);
    static bool encryptData(QByteArray &data, QByteArray rsa_key, QString password, int compression_level = -1);
    static bool decryptData(QByteArray &data, QByteArray rsa_key, QString password, int compression_level = -1);

    static bool decryptTest(QString *text);

private:
    enum CRYPTO_TYPE_T
    {
        AES_DECRYPT,
        AES_ENCRYPT
    };
    struct CRYPTO_PARAMS
    {
        unsigned char key[16];
        unsigned char iv[16];
        CRYPTO_TYPE_T type;
    };

private:
    static bool loadRsaKey(QByteArray *input, QByteArray *output, QByteArray *rsa_key, QString *password, CRYPTO_PARAMS *params);
    static bool dataEncryptDecrypt(QByteArray input, QByteArray &output, CRYPTO_PARAMS *params, int compression_level);
    static QString base64Encode(const unsigned char *bytes_to_encode, unsigned int in_len);
    static std::string base64Decode(QString input);
};


#endif // SSL_H
