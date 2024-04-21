#ifndef _OPENSSL_EVP_H
#define _OPENSSL_EVP_H

#include <openssl/evp.h>

namespace openssl
{
	class CBIO;

	/*********************************************************************************************************
	win32 openssl 默认对称加密算法兼容性
		1. 支持: aes,cast,bf,idea,rc2,rc4,des
		2. 不支持: camellia,seed,rc5
	默认消息摘要算法兼容性
		1.支持: md2,md4,md5,sha,sha256,sha512,ripemd
		2.不支持:mdc2
	*********************************************************************************************************/
	
	const unsigned char EVP_DIGEST_BIT = 0x01;
	const unsigned char EVP_CIPHER_BIT = 0x02;
	const unsigned char EVP_ALL_BIT    = 0x03;
	/**
		@brief 初始化加载算法
		@mask  算法类型: EVP_DIGEST_BIT--消息摘要,EVP_CIPHER_BIT--数据加解密,EVP_ALL_BIT--所有算法
	*/
	void evp_init(unsigned char mask=EVP_ALL_BIT);
	
	/**
		@brief 清除加载的各种算法
	*/
	void evp_clean();

	/**
		@brief base64编码
		@in    输入数据
		@out   输出数据
	*/
	bool b64_encode(CBIO& in,CBIO& out);
	
	/**
		@brief base64解码
		@in    输入数据
		@out   输出数据
	*/
	bool b64_decode(CBIO& in,CBIO& out);

	/**
		@brief    对称加解密
		@param in 输入数据
		@param out 输出数据
		@param pwd 加解密密码
		@param enc true加密,false解密
		@param cp_name 加密算法名称,默认为des_ede3_cbc
		@param md_name 消息摘要算法名称,默认为md5
		@return 操作成功返回true,否则返回false
	*/
	bool crypt(CBIO& in,CBIO& out,const char* pwd,bool enc,const char* cp_name=NULL,const char* md_name=NULL);

	/**
		@brief  消息摘要
		@param in  输入数据
		@param out 输出数据
		@param md_name 摘要算法名称,默认为md5
		@return 操作成功返回true,否则返回false
	*/
	bool digest(CBIO&in, CBIO& out,const char* md_name=NULL);
	
	/**
		@brief 数字签名
		@param privkey 私钥数据
		@param in 输入数据
		@param out 输出数据
		@param pwd 私钥密码
		@param md_name 摘要算法,默认为md5
        @param pkey_cp_name 私钥所用的对称加解密算法,默认为des_ede3_cbc
		@param pkey_md_name 私钥所用的摘要算法,默认为md5
		@return 操作成功返回true,否则返回false
	*/
	bool sign(CBIO& privkey,CBIO& in,CBIO& out,const char* pwd,const char* md_name=NULL,const char* pkey_cp_name=NULL,const char* pkey_md_name=NULL);

	/**
		@brief 验证数字签名
		@param pubkey 公钥数据
		@param in 输入源数据
		@param sign 源数据in签名后的数据
		@param pwd 公钥密码,仅对p12格式数据有效
		@param md_name 签名摘要算法,默认为md5
		@return 操作成功返回true,否则返回false
	*/
    bool verify_sign(CBIO& pubkey,CBIO& in,CBIO& sign,const char* pwd,const char* md_name = NULL);

	/**
		@brief RSA公钥加解密
		@param pubkey 公钥数据
		@param in     输入数据
		@param out    输出数据
		@param enc    true表示加密,false表示解密
		@param pwd    公钥密码,仅对p12格式数据有效
		@return 操作成功返回true,否则返回false
	*/
	bool rsa_public_crypt(CBIO& pubkey,CBIO& in,CBIO& out,bool enc,const char* pwd=NULL);

	/**
		@brief RSA私钥加解密
		@param privkey 私钥数据
		@param in     输入数据
		@param out    输出数据
		@param enc    true表示加密,false表示解密
		@param pwd    当in是pem或der格式时表示私钥密码;当in是p12格式时,表示p12解密密码
		@param cp_name 私钥数据所用的对称加解密算法,默认为des_ede3_cbc
		@param md_name 私钥数据所用的消息摘要算法,默认为md5
		@return 操作成功返回true,否则返回false
	*/
	bool rsa_private_crypt(CBIO& privkey,CBIO& in,CBIO& out,bool enc,const char* pwd=NULL,const char* cp_name=NULL,const char* md_name=NULL);
}

#endif
