#include "openssl_bio.h"
#include "openssl_ca.h"
#include <openssl/pkcs12.h>
#include <boost/smart_ptr.hpp>
using namespace boost;
using namespace openssl;

CBIO::CBIO():m_bio(NULL)
{
	attach();
}

CBIO::CBIO(BIO* bio)
:m_bio(bio)
{
	
}

CBIO::CBIO(const char* file,const char* mode)
:m_bio(NULL)
{
	attach(file,mode);
}

CBIO::CBIO(const void* buf,int size)
:m_bio(NULL)
{
	attach(buf,size);
}

CBIO::~CBIO()
{
	detach();
}

bool CBIO::attach()
{
	detach();
	m_bio = BIO_new(BIO_s_mem());
	if (m_bio) BIO_set_close(m_bio,BIO_CLOSE);
	return NULL!=m_bio;
}

bool CBIO::attach(BIO* bio)
{
	detach();
	return NULL==(m_bio=bio);
}

bool CBIO::attach(const char* file,const char* mode)
{
	detach();
	m_bio = BIO_new_file(file,mode);
	return NULL!=m_bio;
}

bool CBIO::attach(const void* buf,int size)
{
	detach();
	m_bio = BIO_new_mem_buf((void*)buf,size);
	if (m_bio) BIO_set_close(m_bio,BIO_NOCLOSE);
	return NULL!=m_bio;
}

void CBIO::detach()
{
	if (m_bio) 
	{
		BIO_free_all(m_bio); 
		m_bio = NULL;
	}
}

bool CBIO::eof() const
{
	assert(m_bio);
	int ret = BIO_eof(m_bio);
	return 1==ret;
}

int CBIO::write(const void* buf,int len)
{
	assert(m_bio);
	return BIO_write(m_bio,buf,len);
}

int CBIO::read(void* buf,int len)
{
	assert(m_bio);
	return BIO_read(m_bio,buf,len);
}

char* CBIO::get(int& len) 
{
	assert(m_bio && BIO_TYPE_MEM==m_bio->method->type);
	BUF_MEM* p;
	BIO_get_mem_ptr(m_bio,&p);
	len = p->length; 
	return p->data;
}

BUF_MEM* CBIO::get_mem()
{
	assert(m_bio && BIO_TYPE_MEM==m_bio->method->type);
	BUF_MEM* p;
	BIO_get_mem_ptr(m_bio,&p);
	return p;
}

int CBIO::seek(int off)
{
	assert(m_bio);
	return BIO_seek(m_bio,off);
}

int CBIO::reset()
{
	assert(m_bio);
	return BIO_reset(m_bio);
}

int CBIO::flush()
{
	assert(m_bio);
	return BIO_flush(m_bio);
}

EVP_PKEY* CBIO::to_pubkey(const char* pwd)
{
	assert(m_bio);
	X509* x509 = bio_to_x509(*m_bio,pwd);
	if (NULL==x509) return NULL;
	return X509_get_pubkey(x509);
}

EVP_PKEY* CBIO::to_privkey(const char* pwd,int fmt/*=0*/,const char* cp_name/*=NULL*/,const char* md_name/*=NULL*/)
{
	EVP_PKEY* pkey;
	if (0==fmt)
	{
		if((pkey=to_privkey_impl(pwd,1,cp_name,md_name))==NULL)//尝试DER
		{
			BIO_reset(m_bio);
			if((pkey=to_privkey_impl(pwd,2,cp_name,md_name))==NULL)//尝试PEM
			{
				BIO_reset(m_bio);
				pkey=to_privkey_impl(pwd,3,cp_name,md_name);
			}
		}
	}
	else
	{
		pkey = to_privkey_impl(pwd,fmt,cp_name,md_name);
	}
	return pkey;
}

EVP_PKEY* CBIO::to_privkey_impl(const char* pwd,int fmt,const char* cp_name,const char* md_name)
{
	EVP_PKEY *pkey=NULL;

	if (fmt == 1) //der
	{
		if(NULL==pwd)
		{
			pkey=d2i_PrivateKey_bio(m_bio,NULL);
		}
		else
		{
			const EVP_CIPHER* cipher;
			if (cp_name)
				cipher= EVP_get_cipherbyname(cp_name);
			else
				cipher = EVP_des_ede3_cbc();
			if (NULL==cipher) return NULL;

			const EVP_MD* md;
			if (md_name)
				md = EVP_get_digestbyname(md_name);
			else
				md = EVP_md5();
			if (NULL==md) return NULL;

			BIO* dec = BIO_new(BIO_f_cipher());
			if (NULL==dec) return NULL;
			shared_ptr<BIO> sp_dec(dec,BIO_free);

			unsigned char key[EVP_MAX_KEY_LENGTH]={0},iv[EVP_MAX_IV_LENGTH]={0};
			if(!EVP_BytesToKey(cipher,md,NULL,(unsigned char*)pwd,strlen(pwd),1,key,iv))
				return NULL;

			BIO_set_cipher(dec,cipher,key,iv,0);//1-加密、0-解密
			BIO_push(dec, m_bio); 
			BIO_flush(dec);
			pkey = d2i_PrivateKey_bio(dec, NULL);//私钥解密
			BIO_pop(m_bio);
		}
	}
	else if (fmt == 2) //pem
	{
		pkey=PEM_read_bio_PrivateKey(m_bio,NULL,NULL,(void*)pwd);
	}
	else if (fmt == 3) //p12
	{
		PKCS12 *p12 = d2i_PKCS12_bio(m_bio, NULL);
		PKCS12_parse(p12, pwd, &pkey, NULL, NULL);
		PKCS12_free(p12);
	}
	return pkey;
}
