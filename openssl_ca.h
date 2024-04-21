#ifndef _OPENSSL_CA_H
#define _OPENSSL_CA_H

#include <string>
#include <map>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

namespace openssl
{
	class CBIO;

	typedef std::multimap<std::string,std::string> StringMap;
	typedef StringMap x509_subject;
	typedef StringMap x509_issuer;

	X509* bio_to_x509(BIO& bio,const char* pwd);
	int x509_to_bio(X509& x509,BIO& bio,bool pem);
	void x509_name_to_map(X509_NAME& name,StringMap& sm);
	void asn1_utctime_to_tm(ASN1_UTCTIME& asn1_time,struct tm& val);
	void x509_val_to_tm(X509_VAL& val,struct tm* beg,struct tm* end);

	class CX509
	{
	public:
		enum pubkey_type
		{
			PKEY_UnKnown=0,PKEY_RSA,PKEY_DSA,PKEY_EC,PKEY_DH
		};
	public:
		explicit CX509(X509* x509 = NULL);
		CX509(const char* file,const char* pwd=NULL);
		CX509(const void* buf,int len,const char* pwd=NULL);
		~CX509();

		bool attach(X509* x509);
		bool attach(const char* file,const char* pwd=NULL);
		bool attach(const void* buf,int len,const char* pwd=NULL);
		void detach();
		bool dump_file(const char* file,bool pem = true) const;
		char* dump_mem(int& len,bool pem = true) const;

		unsigned char* get_sn(int& len) const;
		void get_sn(std::string& str,bool upper = true,const char c=0) const;
		long get_version() const;
		void get_subject(x509_subject& subject) const;
		void get_algorithm(std::string& str) const;
		void get_issuer(x509_issuer& issuer) const;
		void get_validity(struct tm* beg,struct tm* end) const;

		bool get_pubkey_bits(int& bits) const;
		bool get_pubkey_type(int& type) const;
		char* get_pubkey(int& len,bool der = true) const;
		bool get_pubkey(std::string& str,bool der = true,bool upper = true,const char c=0) const;

		bool verify_validity() const;
		bool verify_crl(CBIO& in) const;
		bool verify_privkey(CBIO& in,const char* pwd,int fmt=0,const char* cp_name=NULL,
			                const char* md_name=NULL) const;
		bool verify_root_cert(CBIO& in,const char* pwd=NULL) const;

		operator X509* () const { return m_x509; }
		X509** operator&() { return &m_x509; }

	private:
		X509* m_x509;
	};

	//////////////////////////////////////////////////////////////////////////////////////////////
	//struct PKCS12;
	class CPkcs12
	{
	public:
		explicit CPkcs12(PKCS12* p12=NULL);
		explicit CPkcs12(const char* file);
		CPkcs12(const void* buf,unsigned int len);
		~CPkcs12();

		bool attach(PKCS12* p12);
		bool attach(const char* file);
		bool attach(const void* buf,unsigned int len);
		void detach();
		bool dump_file(const char* file) const;
		char* dump_mem(int& len) const;

		bool parse(CBIO* cert,CBIO* privkey,CBIO* chain,const char* p12_pwd,const char* pkey_pwd=NULL,
				   bool pem = true,const char* cp_name=NULL,const char* md_name=NULL) const;

		operator PKCS12*() const { return m_p12; }

	private:
		PKCS12* m_p12;
	};
}

#endif
