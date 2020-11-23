#include "Ssl.h"
#include "aes.h"
#include "pem.h"
#include "rsa.h"
#include "conf.h"
#include "evp.h"
#include "err.h"

#define BUFSIZE 4096
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* convert2Char(QString txt)
{
    char* str = (char*)calloc(txt.length()+1, 1);
    strcpy(str, txt.toStdString().c_str());
    return  str;
}
bool isBase64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

bool Ssl::generateKeyPair(QString output)
{
    bool is_ok = true;

    RSA     * rsa = 0;
    BIGNUM  * bne = 0;
    BIO     * bpPublic = 0,
            * bpPrivate = 0;
    int     bits = 2048;
    unsigned long e = RSA_F4;

    try
    {
        bne = BN_new();
        if (!BN_set_word(bne, e))
            throw true;
        rsa = RSA_new();
        if (!RSA_generate_key_ex(rsa, bits, bne, NULL))
            throw  true;

        bpPublic = BIO_new_file(convert2Char(QString("%1/public.pem").arg(output)), "w+");
        if (!PEM_write_bio_RSAPublicKey(bpPublic, rsa))
            throw true;
        bpPrivate = BIO_new_file(convert2Char(QString("%1/private.pem").arg(output)), "w+");
        if (!PEM_write_bio_RSAPrivateKey(bpPrivate, rsa, NULL, NULL, 0, NULL, NULL))
            throw true;
    }
    catch (...)
    {
        is_ok = false;
    }

    BIO_free_all(bpPublic);
    BIO_free_all(bpPrivate);
    RSA_free(rsa);
    BN_free(bne);

    return is_ok;
}
bool Ssl::encryptText(QString *text, QByteArray rsa_key, bool base64_encode)
{
    bool is_ok = true;
    unsigned char *input = 0,
                  *output = 0;
    int ret;

    try
    {
        RSA *rsa = NULL;
        BIO *bio = BIO_new(BIO_s_mem());

        enum key_type {UNKNOWN_KEY, PRIVATE_KEY, PUBLIC_KEY} type = UNKNOWN_KEY;

        if (rsa_key.startsWith("-----BEGIN RSA PUBLIC KEY-----"))
            type = PUBLIC_KEY;
        else if (rsa_key.startsWith("-----BEGIN RSA PRIVATE KEY-----"))
            type = PRIVATE_KEY;
        if (type == UNKNOWN_KEY)
            throw QString("Invalid rsa key");

        BIO_write(bio, (unsigned char*)rsa_key.data(), rsa_key.length());

        switch (type)
        {
        case PRIVATE_KEY: PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, 0); break;
        case PUBLIC_KEY: PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0); break;
        default: break;
        }

        input = (unsigned char*)convert2Char(*text);
        output = (unsigned char*)malloc(AES_BLOCK_SIZE * AES_BLOCK_SIZE);

        int size = text->length();

        switch (type)
        {
        case PRIVATE_KEY: ret = RSA_private_encrypt(size, input, output, rsa, RSA_PKCS1_PADDING); break;
        case PUBLIC_KEY: ret = RSA_public_encrypt(size, input, output, rsa, RSA_PKCS1_PADDING); break;
        default: ret = -1; break;
        }

        if (ret != AES_BLOCK_SIZE*AES_BLOCK_SIZE)
            throw QString("Failed to encrypt");

        if (base64_encode)
            *text = Ssl::base64Encode((const unsigned char*)output, AES_BLOCK_SIZE * AES_BLOCK_SIZE);
        else
            *text = QByteArray::fromRawData((const char*)output, ret);
    }
    catch(QString err)
    {
        *text = err;
        is_ok = false;
    }

    if (input)
        free(input);
    if (output)
        free(output);
    return  is_ok;
}
bool Ssl::decryptText(QString *text, QByteArray rsa_key, bool base64_decode)
{
    bool is_ok = true;
    unsigned char *output = 0;
    std::string input;

    try
    {
        RSA *rsa = NULL;
        BIO *bio = BIO_new(BIO_s_mem());

        output = (unsigned char*)malloc(4096);

        enum key_type {UNKNOWN_KEY, PRIVATE_KEY, PUBLIC_KEY} type = UNKNOWN_KEY;

        if (rsa_key.startsWith("-----BEGIN RSA PUBLIC KEY-----") || rsa_key.startsWith("-----BEGIN PUBLIC KEY-----"))
            type = PUBLIC_KEY;
        else if (rsa_key.startsWith("-----BEGIN RSA PRIVATE KEY-----") || rsa_key.startsWith("-----BEGIN PRIVATE KEY-----"))
            type = PRIVATE_KEY;

        if (type == UNKNOWN_KEY)
            throw QString("Invalid rsa key");

        BIO_write(bio, (unsigned char*)rsa_key.data(), rsa_key.length());

        switch (type)
        {
        case PRIVATE_KEY: PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, 0); break;
        case PUBLIC_KEY: PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0); break;
        default: break;
        }

        int size = AES_BLOCK_SIZE * AES_BLOCK_SIZE;
        int ret;

        (*text) = (*text).trimmed();

        if (base64_decode)
            input = Ssl::base64Decode(*text);
        else
            input = text->toStdString();

        switch(type)
        {
        case PUBLIC_KEY: ret = RSA_public_decrypt(size, (unsigned char*)input.c_str(), output, rsa, RSA_PKCS1_PADDING); break;
        case PRIVATE_KEY: ret = RSA_private_decrypt(size, (unsigned char*)input.c_str(), output, rsa, RSA_PKCS1_PADDING); break;
        default: ret = -1; break;
        }

        if (ret < 0)
            throw QString("Failed to decrypt");

        *text = QByteArray::fromRawData((const char*)output, ret);
    }
    catch (QString err)
    {
        *text = err;
        is_ok = false;
    }

    if (output)
        free(output);
    return  is_ok;
}
bool Ssl::encryptData(QByteArray &data, QByteArray rsa_key, QString password, int compression_level)
{
    bool is_ok = true;
    try
    {
        if (data.isEmpty())
            throw QString("empty data");

        CRYPTO_PARAMS params = {};
        params.type = (CRYPTO_TYPE_T)AES_ENCRYPT;
        QByteArray tmp = data;
        data.clear();

        if (!Ssl::loadRsaKey(&tmp, &data, &rsa_key, &password, &params))
            throw QString(tmp);
        Ssl::dataEncryptDecrypt(tmp, data, &params, compression_level);
    }
    catch (QString err)
    {
        data.clear();
        data = err.toUtf8();
        is_ok = false;
    }

    return is_ok;
}
bool Ssl::decryptData(QByteArray &data, QByteArray rsa_key, QString password, int compression_level)
{
    bool is_ok = true;
    try
    {
        if (data.isEmpty())
            throw QString("empty data");

        CRYPTO_PARAMS params = {};
        params.type = (CRYPTO_TYPE_T)AES_DECRYPT;
        QByteArray tmp = data;
        data.clear();

        if (!Ssl::loadRsaKey(&tmp, &data, &rsa_key, &password, &params))
            throw QString(tmp);

        Ssl::dataEncryptDecrypt(tmp, data, &params, compression_level);
    }
    catch (QString err)
    {
        data = err.toUtf8();
        is_ok = false;
    }

    return is_ok;
}
bool Ssl::loadRsaKey(QByteArray *input, QByteArray *output, QByteArray *rsa_key, QString *password, CRYPTO_PARAMS *params)
{
    bool is_ok = true;
    RSA *rsa = NULL;
    BIO *bio = NULL;

    try
    {
        if (rsa_key->isEmpty())
            throw QString("invalid rsa key");
        int key_type = rsa_key->contains("RSA PRIVATE KEY")? 0 : 1;

        bio = BIO_new(BIO_s_mem());
        {
            BIO_write(bio, (unsigned char*)rsa_key->data(), rsa_key->length());
            if (key_type == 0)
                PEM_read_bio_RSAPrivateKey(bio, &rsa, 0, 0);
            else
                PEM_read_bio_RSAPublicKey(bio, &rsa, 0, 0);

            if (rsa == NULL)
                throw QString("unable to read rsa key");
        }

        int rsa_sz = RSA_size(rsa);
        unsigned char key[rsa_sz];

        QCryptographicHash hash_key(QCryptographicHash::Sha256);
        QCryptographicHash hash_sal(QCryptographicHash::Md5);
        {
            hash_sal.addData(password->toUtf8());
            memcpy(params->iv, (char*)hash_sal.result().data(), AES_BLOCK_SIZE);
        }

        if (params->type == AES_ENCRYPT)
        {
            hash_key.addData(hash_sal.result());
            memcpy(params->key, (char*)hash_key.result().data(), AES_BLOCK_SIZE);

            int key_sz = (key_type == 0)? RSA_private_encrypt(AES_BLOCK_SIZE, params->key, key, rsa, RSA_PKCS1_PADDING) :
                                          RSA_public_encrypt(AES_BLOCK_SIZE, params->key, key, rsa, RSA_PKCS1_PADDING);
            if (key_sz != rsa_sz)
                throw QString("unable to encrypt rsa key");

            output->append((char*)key, rsa_sz);
        }
        else if (params->type == AES_DECRYPT)
        {
            memcpy(key, input->data(), rsa_sz);
            int key_sz = (key_type == 0)? RSA_private_decrypt(rsa_sz, key, params->key, rsa, RSA_PKCS1_PADDING):
                                          RSA_public_decrypt(rsa_sz, key, params->key, rsa, RSA_PKCS1_PADDING);
            if (key_sz != AES_BLOCK_SIZE)
                throw QString("unable to decrypt rsa key");

            unsigned char check[AES_BLOCK_SIZE];
            {
                hash_key.addData(hash_sal.result());
                memcpy(check, (char*)hash_key.result().data(), AES_BLOCK_SIZE);

                if (memcmp(check, params->key, AES_BLOCK_SIZE) != 0)
                    throw QString("wrong password");
            }
        }
    }
    catch (QString err)
    {
        is_ok = false;
        *output = err.toUtf8();
    }

    RSA_free(rsa);
    BIO_free_all(bio);

    return is_ok;
}
bool Ssl::dataEncryptDecrypt(QByteArray input, QByteArray &output, CRYPTO_PARAMS *params, int compression_level)
{
    AES_KEY aes_key;
    int read, pos = 0;
    unsigned char out_buff[BUFSIZE];

    AES_set_encrypt_key(params->key, 128, &aes_key);

    if (params->type == AES_ENCRYPT)
    {
        input = qCompress(input, compression_level);
        qint64 start_addr = 0, length = input.length();

        while (length > 0)
        {
            read = qMin(length, (qint64)BUFSIZE);
            AES_cfb128_encrypt((unsigned char*)input.mid(start_addr, read).data(), out_buff,
                               read, &aes_key, params->iv, &pos, params->type);
            output.append((char*)out_buff, read);

            length -= read;
            start_addr += read;
        }
    }
    else if (params->type == AES_DECRYPT)
    {
        qint64 start_addr = 256, length = input.length() - 256;

        while (length > 0)
        {
            read = qMin(length, (qint64)BUFSIZE);
            AES_cfb128_encrypt((unsigned char*)input.mid(start_addr, read).data(), out_buff,
                               read, &aes_key, params->iv, &pos, params->type);
            output.append((char*)out_buff, read);

            length -= read;
            start_addr += read;
        }
        output = qUncompress(output);
    }

    return true;
}
QString Ssl::base64Encode(const unsigned char *bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return QString::fromStdString(ret);
}
std::string Ssl::base64Decode(QString input)
{
    int i = 0;
    int j = 0;
    int in_ = 0;
    int in_len = input.size();

    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;
    std::string encoded_string = input.toStdString();

    while (in_len-- && ( encoded_string[in_] != '=') && isBase64(encoded_string[in_]))
    {
        char_array_4[i++] = encoded_string[in_]; in_++;

        if (i ==4)
        {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }
    if (i)
    {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

bool Ssl::decryptTest(QString *text)
{
    QString encryptedText = *text;
    std::string str = base64Decode(encryptedText);

    QCryptographicHash hash(QCryptographicHash::Sha256);
    hash.addData(QString("127.0.0.1442020mount -o rw,union,update /").toUtf8());
    QByteArray key = hash.result().mid(0, 32);
    QByteArray iv(16, '\x00');

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char plaintext[128];

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        qDebug() << "failed to create ctx";
        abort();
        return false;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.constData(), (const unsigned char*)iv.constData()))
    {
        qDebug() << "failed to init decryption";
        abort();
        return false;
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, (const unsigned char*)str.c_str(), str.length()))
    {
        qDebug() << "failed to decrypt";
        abort();
        return false;
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext+len, &len))
    {
        qDebug() << "failed to final decrypt";
        abort();
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *text = QString::fromUtf8((char*)plaintext, plaintext_len); // mount -o rw,uion,update /

    return true;
}
