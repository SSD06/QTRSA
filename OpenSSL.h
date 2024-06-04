#ifndef OPENSSL_HPP
#define OPENSSL_HPP
#include<QtCore>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define BEGIN_RSA_PUBLIC_KEY    "BEGIN RSA PUBLIC KEY"
#define BEGIN_RSA_PRIVATE_KEY   "BEGIN RSA PRIVATE KEY"
#define BEGIN_PUBLIC_KEY        "BEGIN PUBLIC KEY"
#define BEGIN_PRIVATE_KEY       "BEGIN PRIVATE KEY"
#define KEY_LENGTH              1024
enum class KEY_LENG:int
{
    KEY_1024=1024,
    KEY_2048=2048,
    KEY_4096=4096
};
//公钥加密
QString rsaPubEncrypt(const QString &strPlainData, const QString &strPubKey);
//公钥解密
QString rsaPubDecrypt(const QString &strDecryptData, const QString &strPubKey);
//私钥加密
QString rsaPriEncrypt(const QString &strPlainData, const QString &strPriKey);
//私钥解密
QString rsaPriDecrypt(const QString &strDecryptData, const QString &strPriKey);
//生成密钥对
QStringList generateRSAKey();

QStringList generateRSAKey(KEY_LENG leng);

QString generateRSAPUBKey(QString str);

#endif // OPENSSL_HPP
