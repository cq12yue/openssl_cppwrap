#include "openssl_bio.h"
#include "openssl_evp.h"
#include <openssl/pkcs12.h>
#include <fstream>
#include <boost/smart_ptr.hpp>

#define BOOST_MEM_FN_ENABLE_STDCALL
#define BOOST_MEM_FN_ENABLE_FASTCALL
#define BOOST_MEM_FN_ENABLE_CDECL
#include <boost/mem_fn.hpp>
using namespace std;
using namespace boost;

/*********************************************************************************************************
	2011-11-25 增加evp_init,evp_clean函数,将算法装载和卸载独立出来,避免同其它使用openssl的模块冲突                                                                     
*********************************************************************************************************/

void openssl::evp_init(unsigned char mask)
{
	if(mask&EVP_CIPHER_BIT)
	    OpenSSL_add_all_ciphers();
	else if (mask&EVP_DIGEST_BIT)
		OpenSSL_add_all_digests();
	else
		OpenSSL_add_all_algorithms();
}

void openssl::evp_clean()
{
	EVP_cleanup();
}

bool openssl::b64_encode(CBIO& in,CBIO& out)
{
	unsigned char ibuf[1024],obuf[(1024+2)/3*4];
	int ilen,olen;
	while (!in.eof())
	{
		ilen = in.read(ibuf,sizeof(ibuf));
		if (ilen <= 0) break;
		olen = EVP_EncodeBlock(obuf,ibuf,ilen);	
		if (olen <= 0) return false; 
		if (out.write(obuf,olen)<=0)
			return false;
	}
	return out.flush()>0;
}

bool openssl::b64_decode(CBIO& in,CBIO& out)
{
	unsigned char ibuf[1024],obuf[(1024+3)/4*3];
	int ilen,olen;
	while (!in.eof())
	{
		ilen = in.read(ibuf,sizeof(ibuf));
		if (ilen <= 0) break;
		olen = EVP_DecodeBlock(obuf,ibuf,ilen);	
		if (0==BIO_pending(in))
		{
			while('='==ibuf[--ilen]) 
				--olen;
		}
		if (olen <= 0) return false; 
		if (out.write(obuf,olen)<=0)
			return false;
	}
	return out.flush()>0;
}

bool openssl::crypt(CBIO& in,CBIO& out,const char* pwd,bool enc,const char* cp_name/*=NULL*/,const char* md_name/*=NULL*/)
{
	const EVP_CIPHER* cipher;
	if (cp_name)
		cipher = EVP_get_cipherbyname(cp_name);
	else
		cipher = EVP_des_ede3_cbc();
	if (NULL==cipher) return false;

	const EVP_MD* md;
	if (md_name)
		md = EVP_get_digestbyname(md_name);
	else
		md = EVP_md5();
	if (NULL==md) return false;

	unsigned char key[EVP_MAX_KEY_LENGTH]={0},iv[EVP_MAX_IV_LENGTH]={0};
	if(!EVP_BytesToKey(cipher,md,NULL,(const unsigned char*)pwd,pwd?strlen(pwd):0,1,key,iv))
		return false;

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	if(!EVP_CipherInit_ex(&ctx,cipher,NULL,key,iv,enc?1:0))
		return false;
	shared_ptr<EVP_CIPHER_CTX> sp_ctx(&ctx,EVP_CIPHER_CTX_cleanup);
	
	char ibuf[1024],obuf[1024+EVP_MAX_BLOCK_LENGTH];
	int ilen,olen;

	while (true)
	{
		ilen = in.read(ibuf,sizeof(ibuf));
		if (ilen<=0) break;
		if(!EVP_CipherUpdate(&ctx,(unsigned char*)obuf,&olen,(const unsigned char*)ibuf,ilen))
			return false;
		if (out.write(obuf,olen)<=0)
			return false;
	}
	if(!EVP_CipherFinal_ex(&ctx,(unsigned char*)obuf,&olen))       
		return false;

	if (out.write(obuf,olen)<=0 || out.flush()<=0) 
		return false;
	return true;
}

bool openssl::digest(CBIO& in, CBIO& out,const char* md_name/*=NULL*/)
{
	const EVP_MD* md;
	if (md_name)
		md = EVP_get_digestbyname(md_name);
	else
		md = EVP_md5();
	if (NULL==md) return false;

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	if(!EVP_DigestInit_ex(&ctx,md,NULL))
		return false;
	shared_ptr<EVP_MD_CTX> sp_ctx(&ctx,EVP_MD_CTX_cleanup);

	char ibuf[1024]; int len;
	while(!in.eof())
	{
		len = in.read(ibuf,sizeof(ibuf));
		if (len>0)
		{
			if(!EVP_DigestUpdate(&ctx,ibuf,len))
				return false;
		}
	}
	char obuf[EVP_MAX_MD_SIZE];
	if(!EVP_DigestFinal_ex(&ctx,(unsigned char*)obuf,(unsigned int*)&len))
		return false;

	if (out.write(obuf,len)<=0 || out.flush()<=0) 
		return false;
	return true;
}

bool openssl::sign(CBIO& privkey,CBIO& in,CBIO& out,const char* pwd,const char* md_name/*=NULL*/,const char* pkey_cp_name/*=NULL*/,const char* pkey_md_name/*=NULL*/)
{
	EVP_PKEY* pkey = privkey.to_privkey(pwd,0,pkey_cp_name,pkey_md_name);
	if (pkey == NULL) return false;
	shared_ptr<EVP_PKEY> sp_pkey(pkey,EVP_PKEY_free);

	const EVP_MD* md;
	if (md_name)
		md = EVP_get_digestbyname(md_name);
	else
		md = EVP_md5();
	if (NULL==md) return false;

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	if(!EVP_SignInit_ex(&ctx,md,NULL))
		return false;
	shared_ptr<EVP_MD_CTX> sp_ctx(&ctx,EVP_MD_CTX_cleanup);

	char ibuf[1024]; int len;
	while(!in.eof())
	{
		len = in.read(ibuf,sizeof(ibuf));
		if (len>0)
		{
			if(!EVP_SignUpdate(&ctx,ibuf,len))
				return false;
		}
		else break;
	}

	len =EVP_PKEY_size(pkey);
	unsigned char* obuf = new (std::nothrow) unsigned char[len];
	if (NULL==obuf) return false;
	scoped_array<unsigned char> sp_buf(obuf);

	if(!EVP_SignFinal(&ctx,obuf,(unsigned int*)&len,pkey))
		return false;

	if (out.write(obuf,len)<=0 || out.flush()<=0) 
		return false;
	return true;
}

bool openssl::verify_sign(CBIO& pubkey,CBIO& in,CBIO& sign,const char* pwd,const char* md_name/*=NULL*/)
{
	EVP_PKEY* pkey = pubkey.to_pubkey(pwd);
	if (pkey == NULL) return false;
	shared_ptr<EVP_PKEY> sp_pkey(pkey,EVP_PKEY_free);

	const EVP_MD* md;
	if (md_name)
		md = EVP_get_digestbyname(md_name);
	else
		md = EVP_md5();
	if (NULL==md) return false;

	EVP_MD_CTX ctx;
	EVP_MD_CTX_init(&ctx);
	if(!EVP_VerifyInit_ex(&ctx,md,NULL))
		return false;
	shared_ptr<EVP_MD_CTX> sp_ctx(&ctx,EVP_MD_CTX_cleanup);

	char ibuf[1024]; int len;
	while(!in.eof())
	{
		len = in.read(ibuf,sizeof(ibuf));
		if (len<=0) break;
		if(!EVP_VerifyUpdate(&ctx,ibuf,len))
			return false;
	}

	len =EVP_PKEY_size(pkey);
	unsigned char* obuf = new (std::nothrow) unsigned char[len];
	if (NULL==obuf) return false;
	scoped_array<unsigned char> sp_buf(obuf);
	
	for (int ret,tran=0;tran<len;)
	{
		ret = sign.read(obuf+tran,len-tran);
		if (ret<=0) return false;
		tran += ret;
	}
	
	if(!EVP_VerifyFinal(&ctx,obuf,len,pkey))
		return false;
	return true;
}

bool openssl::rsa_public_crypt(CBIO& pubkey,CBIO& in,CBIO& out,bool enc,const char* pwd/*=NULL*/)
{
	EVP_PKEY* pkey = pubkey.to_pubkey(pwd);
	if (NULL==pkey) return false;
	shared_ptr<EVP_PKEY> sp_pkey(pkey,EVP_PKEY_free);
	
	RSA* rsa = EVP_PKEY_get1_RSA(pkey);
	if (NULL==rsa) return false;
	shared_ptr<RSA> sp_rsa(rsa,RSA_free);
	
	//注意调用约定
	typedef int(*pfn_crypt)(int, const unsigned char*,unsigned char*,RSA*,int);
	pfn_crypt pcrypt;
	int isize,osize;
	if (enc)
	{
		pcrypt = RSA_public_encrypt;
		osize = RSA_size(rsa);
		isize = osize - 11;
	}
	else
	{
		pcrypt = RSA_public_decrypt;
		isize = RSA_size(rsa);
		osize = isize - 11;
	}
	
	unsigned char* ibuf = new (std::nothrow) unsigned char[isize];
	if (NULL==ibuf) return false;
	scoped_array<unsigned char> sp_ibuf(ibuf);
	unsigned char* obuf = new (std::nothrow) unsigned char[osize];
	if (NULL==obuf) return false;
	scoped_array<unsigned char> sp_obuf(obuf);

	int ilen,olen;
	while(!in.eof())	
	{
		ilen = in.read(ibuf,isize);
		if (ilen<=0) break;
		olen = pcrypt(ilen,ibuf,obuf,rsa,RSA_PKCS1_PADDING);
		if (-1==olen||out.write(obuf,olen)<=0)
			return false;
	}
	if (out.flush()<=0)
		return false;
	return true;
}

bool openssl::rsa_private_crypt(CBIO& privkey,CBIO& in,CBIO& out,bool enc,const char* pwd/*=NULL*/,const char* cp_name/*=NULL*/,const char* md_name/*=NULL*/)
{
	EVP_PKEY* pkey = privkey.to_privkey(pwd,0,cp_name,md_name);
	if (NULL==pkey) return false;
	shared_ptr<EVP_PKEY> sp_pkey(pkey,EVP_PKEY_free);
	RSA* rsa = EVP_PKEY_get1_RSA(pkey);
	if (NULL==rsa) return false;
	shared_ptr<RSA> sp_rsa(rsa,RSA_free);

	//注意调用约定
	typedef int(*pfn_crypt)(int, const unsigned char*,unsigned char*,RSA*,int);
	pfn_crypt pcrypt;
	int isize,osize;
	if (enc)
	{
		pcrypt = RSA_private_encrypt;
		osize = RSA_size(rsa);
		isize = osize - 11;
	}
	else
	{
		pcrypt = RSA_private_decrypt;
		isize = RSA_size(rsa);
		osize = isize - 11;
	}

	unsigned char* ibuf = new (std::nothrow) unsigned char[isize];
	if (NULL==ibuf) return false;
	scoped_array<unsigned char> sp_ibuf(ibuf);
	unsigned char* obuf = new (std::nothrow) unsigned char[osize];
	if (NULL==obuf) return false;
	scoped_array<unsigned char> sp_obuf(obuf);

	int ilen,olen;
	while(!in.eof())	
	{
		ilen = in.read(ibuf,isize);
		if (ilen<=0) break;
		olen = pcrypt(ilen,ibuf,obuf,rsa,RSA_PKCS1_PADDING);
		if (-1==olen||out.write(obuf,olen)<=0)
			return false;
	}
	if (out.flush()<=0)
		return false;
	return true;
}
