#include "openssl_ca.h"
#include "openssl_bio.h"
#include <fstream>
#include <openssl/pem.h>
#include <boost/smart_ptr.hpp>
using namespace std;
using namespace boost;
using namespace openssl;

/*********************************************************************************************************
	2011-11-16 改正了CPkcs12 parse 方法提取der格式且密码非空时,私钥并没有加密时的BUG    
	经测试发现如下情况:
	1) 当数据源是der格式且包含无论是否加密过的私钥时,则提取x509和公钥成功,提取私钥失败
	   当数据源是der格式且仅包括无论是否加密过的私钥时,提供私钥均成功
	2) 当数据源是pem格式且包含无论是否加密过的私钥时,则提取x509、公钥、私钥均成功
    3) PEM_write_bio_PrivateKey: 
	   当私钥未被加密时,忽略解密时提供的密码;当私钥被加密时,则解密时必须提供对应密码
	   不接受空密码,使用空密码加解密会发生错误
*********************************************************************************************************/

template<typename charT>
static std::basic_string<charT> mem2hex(const void* src, size_t size, bool upper = true,charT tag = 0)
{
  std::basic_string<charT> strDest;
  strDest.reserve(2*size);
  
  unsigned char* pSrc = (unsigned char*)src;
  unsigned char  buf[2];

  for (size_t i = 0; i < size; ++i) {
    unsigned char c0 = *pSrc >> 4;  
    if ( c0 >= 0x0 && c0 <= 0x9)
      buf[0] = c0 - 0 + '0';
    else 
      buf[0] = c0 - 10 + (upper ? 'A' : 'a');
    
    unsigned char c1 = *pSrc++ & 0x0F;
    if ( c1 >= 0x0 && c1 <= 0x9)
      buf[1] = c1 - 0 + '0';
    else 
      buf[1] = c1 - 10 + (upper ? 'A' : 'a');
    
    strDest += (charT)buf[0];
    strDest += (charT)buf[1];
    if (tag != 0)  strDest += tag;
  }
  return strDest;
}

X509* openssl::bio_to_x509(BIO& bio,const char* pwd)
{
	X509* x509 = d2i_X509_bio(&bio,NULL);
	if(NULL==x509)
	{ 
		BIO_reset(&bio);
		x509 = PEM_read_bio_X509(&bio,NULL,NULL,NULL);
	}
	if (NULL==x509)
	{
		BIO_reset(&bio);
		PKCS12 *p12 = d2i_PKCS12_bio(&bio,NULL);
		if (NULL==p12) return NULL;
		PKCS12_parse(p12, pwd, NULL, &x509, NULL);
		PKCS12_free(p12);
	}
	return x509;
}

int openssl::x509_to_bio(X509& x509,BIO& bio,bool pem)
{
	int ret;
	if (pem)
		ret = PEM_write_bio_X509(&bio,&x509);
	else
		ret = i2d_X509_bio(&bio,&x509);
	return ret;
}

void openssl::x509_name_to_map(X509_NAME& name,StringMap& sm)
{
	X509_NAME_ENTRY* entry;
	ASN1_OBJECT* obj;
	ASN1_STRING* str;
	char objtmp[128] = {0};
	int fn_nid = 0;

	setlocale(LC_CTYPE, ""); 

	int num = X509_NAME_entry_count(&name);
	for(int i = 0;i < num;i ++)
	{
		entry = X509_NAME_get_entry(&name,i);

		obj = X509_NAME_ENTRY_get_object(entry);
		fn_nid = OBJ_obj2nid(obj);
		if(fn_nid == NID_undef)
		{
			OBJ_obj2txt(objtmp, sizeof(objtmp), obj, 1);
		}
		else
		{
			const char* objbuf = OBJ_nid2sn(fn_nid);
			strcpy(objtmp,objbuf);
		}

		str = X509_NAME_ENTRY_get_data(entry);
		int len = 0;
		char* tmp = NULL; 
		if (str && ASN1_STRING_type(str) == V_ASN1_UTF8STRING)
		{
			len = ASN1_STRING_length(str);
			if (len >= 0)
			{
				tmp = (char*)OPENSSL_malloc(len+1);
				if (tmp)
				{
					memcpy(tmp, ASN1_STRING_data(str), len);
					tmp[len] = '\0';
				}
			}
		}
		else 
		{
			len = ASN1_STRING_to_UTF8((unsigned char**)&tmp, str);
		}
		if (tmp)
		{
			sm.insert(make_pair(objtmp,utf8_to_ansi(tmp,len)));
			OPENSSL_free(tmp);
		}
		OBJ_cleanup();
	}
}

void openssl::asn1_utctime_to_tm(ASN1_UTCTIME& asn1_time,struct tm& val)
{
	memset(&val,0,sizeof(tm));

#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
	val.tm_year=g2(asn1_time.data);
	if(val.tm_year < 50) val.tm_year += 100;
	val.tm_mon=g2(asn1_time.data+2);
	val.tm_mday=g2(asn1_time.data+4);
	val.tm_hour=g2(asn1_time.data+6);
	val.tm_min=g2(asn1_time.data+8);
	val.tm_sec=g2(asn1_time.data+10);
#undef g2

	TIME_ZONE_INFORMATION TimeZoneInformation;
	GetTimeZoneInformation(&TimeZoneInformation);

	val.tm_year += 1900;
	val.tm_hour -= TimeZoneInformation.Bias/60;
}

void openssl::x509_val_to_tm(X509_VAL& val,struct tm* beg,struct tm* end)
{
	if (beg) asn1_utctime_to_tm(*val.notBefore,*beg);
	if (end) asn1_utctime_to_tm(*val.notAfter,*end);
}

//////////////////////////////////////////////////////////////////////////////////////////////
CX509::CX509(X509* x509 /*=NULL*/)
:m_x509(x509)
{
	
}

CX509::CX509(const char* file,const char* pwd/*=NULL*/)
:m_x509(NULL)
{
	attach(file,pwd);
}

CX509::CX509(const void* buf,int len,const char* pwd/*=NULL*/)
:m_x509(NULL)
{
	attach(buf,len);
}

CX509::~CX509()
{
	detach();
}

bool CX509::attach(X509* x509)
{
	detach();
	return NULL==(m_x509 = x509); 
}

bool CX509::attach(const char* file,const char* pwd/*=NULL*/)
{
	detach();
	CBIO bio(BIO_new_file(file,"rb"));
	if (NULL==bio) return false;
	
	m_x509 = bio_to_x509(*bio,pwd);
	return NULL==m_x509;
}

bool CX509::attach(const void* buf,int len,const char* pwd/*=NULL*/)
{
	detach();
	CBIO bio(BIO_new_mem_buf((void*)buf,len));
	if (NULL==bio) return false;
	
	BIO_set_close(bio,BIO_NOCLOSE);
	m_x509 = bio_to_x509(*bio,pwd);
	return NULL==m_x509;
}

void CX509::detach()
{
	if(m_x509) 
	{
		X509_free(m_x509);
		m_x509 = NULL;
	}
}

bool CX509::dump_file(const char* file,bool pem /*= true*/) const
{
	assert(m_x509);
	CBIO bio(BIO_new_file(file,"wb"));
	if (NULL==bio) return false;
	
	return 0 != x509_to_bio(*m_x509,*bio,pem);
}

char* CX509::dump_mem(int& len,bool pem /*= true*/) const
{
	assert(m_x509);
	
	len = 0;
	CBIO bio(BIO_new(BIO_s_mem()));
	if (NULL==bio) return NULL;

	int ret = x509_to_bio(*m_x509,*bio,pem);
	if (!ret) return NULL;

	BUF_MEM* p = NULL; 
	BIO_get_mem_ptr(bio,&p);
	char* buf = new (std::nothrow) char[p->length];
	if (buf)
	{
		memcpy(buf,p->data,p->length);
		len = p->length;	
	}
	return buf;
}

unsigned char* CX509::get_sn(int& len) const
{
	assert(m_x509);
	ASN1_INTEGER* ai = X509_get_serialNumber(m_x509);
	len = ai->length;
	return ai->data;
}

void CX509::get_sn(string& str,bool upper/*=true*/,const char c/*=0*/) const
{
	assert(m_x509);
	ASN1_INTEGER* ai = X509_get_serialNumber(m_x509);
	str = mem2hex<char>(ai->data,ai->length,upper,c);
}

long CX509::get_version() const
{
	assert(m_x509);
	return X509_get_version(m_x509)+1;
}

void CX509::get_subject(x509_subject& subject) const
{
	assert(m_x509);
	x509_name_to_map(*X509_get_subject_name(m_x509),subject);
}

void CX509::get_algorithm(std::string& str) const
{
	assert(m_x509);
	char buf[1024];
	i2t_ASN1_OBJECT(buf,sizeof(buf),m_x509->cert_info->signature->algorithm);
	str = buf;
}

void CX509::get_issuer(x509_issuer& issuer) const
{
	assert(m_x509);
	x509_name_to_map(*X509_get_issuer_name(m_x509),issuer);
}

void CX509::get_validity(struct tm* beg,struct tm* end) const
{
	assert(m_x509);
	x509_val_to_tm(*m_x509->cert_info->validity,beg,end);
}

bool CX509::get_pubkey_bits(int& bits) const
{
	assert(m_x509);

	EVP_PKEY* pkey = X509_get_pubkey(m_x509);
	if(pkey == NULL) return false;
	bits = EVP_PKEY_bits(pkey);
	EVP_PKEY_free(pkey);
	return true;
}

bool CX509::get_pubkey_type(int& type) const
{
	EVP_PKEY* pkey = X509_get_pubkey(m_x509);
	if(pkey == NULL) return false;
	
	switch(EVP_PKEY_type(pkey->type))
	{
		case EVP_PKEY_RSA:	type = PKEY_RSA;break;
		case EVP_PKEY_EC:	type = PKEY_EC;break;
		case EVP_PKEY_DSA:	type = PKEY_DSA;break;
		case EVP_PKEY_DH:	type = PKEY_DH;break;
		default: type = PKEY_UnKnown;break;
	}
	EVP_PKEY_free(pkey);
	return true;
}

char* CX509::get_pubkey(int& len,bool der /*= true*/) const
{
	assert(m_x509);

	len = 0;
	EVP_PKEY* pkey = X509_get_pubkey(m_x509);
	if(pkey == NULL) return NULL;
	shared_ptr<EVP_PKEY> sp_pkey(pkey,EVP_PKEY_free);

	CBIO bio(BIO_new(BIO_s_mem()));
	if (NULL==bio) return NULL;
		
	typedef void (*pfn_free)(void*);
	typedef int (*pfn_i2d)(BIO*,void*);
	pfn_free pfree;
	pfn_i2d pi2d;
	void* key = NULL;

	switch(EVP_PKEY_type(pkey->type))
	{
	case EVP_PKEY_RSA:
		{
			RSA* rsa = EVP_PKEY_get1_RSA(pkey);
			if (NULL==rsa) return NULL;
			key = rsa;
			pi2d = der ? (pfn_i2d)i2d_RSAPublicKey_bio:(pfn_i2d)PEM_write_bio_RSAPublicKey;
			pfree = (pfn_free)RSA_free;
		}
		break;

	case EVP_PKEY_DSA:
		{
			DSA* dsa = EVP_PKEY_get1_DSA(pkey); 
			if (NULL==dsa) return NULL;
			key = dsa;
			pi2d = (pfn_i2d)(der ? i2d_DSA_PUBKEY_bio : PEM_write_bio_DSA_PUBKEY);
			pfree = (pfn_free)DSA_free;
		}
		break;

	case EVP_PKEY_EC:
		{
			EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
			if (NULL==ec) return NULL;
			key = ec;
			pi2d = (pfn_i2d) (der ? i2d_EC_PUBKEY_bio : PEM_write_bio_EC_PUBKEY);
			pfree = (pfn_free)EC_KEY_free;
		}
		break;
	
	}
	if (NULL==key) return NULL;
	
	BUF_MEM *p = NULL;
	if (!pi2d(bio,key)) return NULL;

	BIO_get_mem_ptr(bio, &p);
	char* buf = new (std::nothrow) char[p->length];
	if (buf)
	{
		memcpy(buf,p->data,p->length);
		len = p->length;
	}
	pfree(key);
	return buf;
}

bool CX509::get_pubkey(std::string& str,bool der/*=true*/,bool upper/*=true*/,const char c/*=0*/) const
{
	int len;
	char* p = get_pubkey(len,der);
	if (NULL==p) return false;
	if (der)
		str = mem2hex<char>(p,len,upper,c);
	else
		str.assign(p,len);
	delete []p;
	return true;
}

bool CX509::verify_validity() const
{
	assert(m_x509);

	time_t ct; 	time(&ct);
	ASN1_UTCTIME *before=X509_get_notBefore(m_x509),*after=X509_get_notAfter(m_x509);
	return ASN1_UTCTIME_cmp_time_t(before,ct)<0 && ASN1_UTCTIME_cmp_time_t(after,ct)>0;
}

bool CX509::verify_crl(CBIO& in) const
{
	assert(m_x509);

	X509_CRL* crl = d2i_X509_CRL_bio(in,NULL); 
	if( NULL==crl)
	{
		in.reset();
		crl = PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
	}
	if (NULL==crl) return false;
	
	shared_ptr<X509_CRL> sp_crl(crl,X509_CRL_free);
	STACK_OF(X509_REVOKED) *revoked = crl->crl->revoked;

	shared_ptr<X509_REVOKED> sp_rc;
	ASN1_INTEGER *serial = X509_get_serialNumber(m_x509);
	for(int i=0, num = sk_X509_REVOKED_num(revoked);i < num;i++)
	{
		X509_REVOKED* rc = sk_X509_REVOKED_pop(revoked);	//leak
		sp_rc.reset(rc,X509_REVOKED_free);
		if(ASN1_INTEGER_cmp(serial,rc->serialNumber)==0)
		{
			return false;
		}
	}
	return true;
}

bool CX509::verify_privkey(CBIO& in,const char* pwd,int fmt/*=0*/,const char* cp_name/*=NULL*/,const char* md_name/*=NULL*/) const
{
	assert(m_x509);

	EVP_PKEY *pkey = in.to_privkey(pwd,fmt,cp_name,md_name);
	if (NULL==pkey) return false;
	shared_ptr<EVP_PKEY> sp(pkey,EVP_PKEY_free);	
	return 0!=X509_check_private_key(m_x509,pkey);
}

bool CX509::verify_root_cert(CBIO& in,const char* pwd/*=NULL*/) const
{
	assert(m_x509);

	EVP_PKEY* pkey = in.to_pubkey(pwd);
	if (NULL==pkey) return false;
	shared_ptr<EVP_PKEY> sp(pkey,EVP_PKEY_free);	
	return 0!=X509_verify(m_x509,pkey);
}

//////////////////////////////////////////////////////////////////////////////////////////////
CPkcs12::CPkcs12(PKCS12* p12)
:m_p12(p12)
{

}

CPkcs12::CPkcs12(const char* file)
:m_p12(NULL)
{
	attach(file);
}

CPkcs12::CPkcs12(const void* buf,unsigned int len)
:m_p12(NULL)
{
	attach(buf,len);
}

CPkcs12::~CPkcs12()
{
	detach();
}

bool CPkcs12::attach(PKCS12* p12)
{
	return NULL==(m_p12 = p12);
}

bool CPkcs12::attach(const char* file)
{
	detach();
	CBIO bio(BIO_new_file(file,"rb"));
	if (NULL==bio) return false;

	m_p12 = d2i_PKCS12_bio(bio,NULL);
	bio.reset();

	return NULL==m_p12;
}

bool CPkcs12::attach(const void* buf,unsigned int len)
{
	detach();
	CBIO bio(BIO_new_mem_buf((void*)buf,len));
	if (NULL==bio) return false;

	BIO_set_close(bio,BIO_NOCLOSE);
	m_p12 = d2i_PKCS12_bio(bio,NULL);
	return NULL==m_p12;
}

void CPkcs12::detach()
{
	if(m_p12)
	{
		PKCS12_free(m_p12);
		m_p12 = NULL;
	}
}

bool CPkcs12::dump_file(const char* file) const
{
	int len;
	char* buf = dump_mem(len);
	if (NULL==buf) return false;

	shared_array<char> sp_mem(buf);
	CBIO out(file,"wb");
	if (NULL==out) return false;
	if (out.write(buf,len)<=0||out.flush()<=0)
		return false;
	return true;
}

char* CPkcs12::dump_mem(int& len) const
{
	assert(m_p12);

	len = 0;
	CBIO bio(BIO_new(BIO_s_mem()));
	if (NULL==bio) return NULL;

	i2d_PKCS12_bio(bio,m_p12);
	BUF_MEM* p = NULL;
	BIO_get_mem_ptr(bio,&p);
	char* buf = new (std::nothrow) char[p->length];
	if (buf)
	{
		memcpy(buf,p->data,p->length);
		len = p->length;
	}
	return buf;
}

bool CPkcs12::parse(CBIO* cert,CBIO* privkey,CBIO* chain,const char* p12_pwd,const char* pkey_pwd/*=NULL*/,
		            bool pem /*=true*/,const char* cp_name/*=NULL*/,const char* md_name/*=NULL*/) const
{
	assert(m_p12);
	
    EVP_PKEY* pkey = NULL; 
	CX509 x509;
	STACK_OF(X509)* ca = NULL;

	if (0==PKCS12_parse(m_p12,p12_pwd,&pkey,&x509,&ca)) 
		return false;

	shared_ptr<EVP_PKEY> sp_pkey;
	if (pkey) sp_pkey.reset(pkey,EVP_PKEY_free);

	shared_ptr<STACK_OF(X509)> sp_ca;
	if (ca) sp_ca.reset(ca,sk_free);

	int ret;
	if (x509 && cert)
	{
		pem ? ret = PEM_write_bio_X509(*cert,x509) : ret = i2d_X509_bio(*cert,x509);
		if (ret<=0) return false;
	}

	BIO* bio;
	if (pkey)
	{
		bio = (privkey ? *privkey : (cert ? *cert : (BIO*)NULL));
		if (bio)
		{
			const EVP_CIPHER* cipher;
			const EVP_MD* md;

			bool enc = pkey_pwd ? true : false;
			if (enc)
			{
				if (cp_name)
					cipher = EVP_get_cipherbyname(cp_name);
				else
					cipher = EVP_des_ede3_cbc();
				if (NULL==cipher) return false;

				if (md_name)
					md = EVP_get_digestbyname(md_name);
				else
					md = EVP_md5();
				if (NULL==md) return false;
			}
			if (pem)
			{
				enc ? ret = PEM_write_bio_PrivateKey(bio,pkey,cipher,NULL,0,NULL,(void*)pkey_pwd) : 
					  ret = PEM_write_bio_PrivateKey(bio,pkey,NULL,NULL,0,0,NULL);//私钥不加密
			    if (0==ret) return false;
			}
			else
			{
				if(enc)
				{
					unsigned char key[EVP_MAX_KEY_LENGTH]={0},iv[EVP_MAX_IV_LENGTH]={0};
					CBIO bio_enc(BIO_new(BIO_f_cipher()));
					if (NULL==bio_enc) return false;

					if(!EVP_BytesToKey(cipher,md,NULL,(unsigned char*)pkey_pwd,strlen(pkey_pwd),1,key,iv))
						return false;

					BIO_set_cipher(bio_enc,cipher,key,iv,1);//1-加密、0-解密
					BIO_push(bio_enc,bio); 
					ret = i2d_PrivateKey_bio(bio_enc,pkey);//私钥加密
					BIO_flush(bio_enc);
					BIO_pop(bio);

					if (ret<=0) return false;
				}
				else
				{
					if (i2d_PrivateKey_bio(bio,pkey)<=0)  return false;
				}
			}
		}
		
	}
	if (ca)
	{
		bio = (chain ? *chain : (cert ? *cert : (BIO*)NULL));
		if (bio)
		{
			for (int i=0;i<sk_X509_num(ca);++i)
			{
				X509* x = sk_X509_value(ca,i);
				pem ? ret =  PEM_write_bio_X509(bio,x) : ret = i2d_X509_bio(bio,x);
				if (ret<=0) return false;
			}
		}	
	}
	return true;
}
