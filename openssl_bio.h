#ifndef _OPENSSL_BIO_H
#define _OPENSSL_BIO_H

#include <openssl/bio.h>

namespace openssl
{
	class CBIO
	{
	public:
		CBIO();
		explicit CBIO(BIO* bio);
		CBIO(const char* file,const char* mode);
		CBIO(const void* buf,int size);
		~CBIO();

		bool attach();
		bool attach(BIO* bio);
		bool attach(const char* file,const char* mode);
		bool attach(const void* buf,int size);
		void detach();

		bool eof() const;
		int write(const void* buf,int len);
		int read(void* buf,int len);
		char* get(int& len);
		BUF_MEM* get_mem();
		int seek(int off);
		int reset();
		int flush();

		EVP_PKEY* to_privkey(const char* pwd,int fmt = 0,const char* cp_name=NULL,const char* md_name=NULL);
		EVP_PKEY* to_pubkey(const char* pwd);

		operator BIO*() const { return m_bio; }
		
	protected:
		EVP_PKEY* to_privkey_impl(const char* pwd,int fmt,const char* cp_name,const char* md_name);
	
	private:
		BIO* m_bio;
	};
}

#endif
