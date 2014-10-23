/** 
 * base64加解码
 *
 */



#ifndef _TS_BASE_H_
#define _TS_BASE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef _TCHAR_DEFINED
typedef char TCHAR, *PTCHAR;
typedef unsigned char TBYTE , *PTBYTE ;
#define _TCHAR_DEFINED
#endif /* !_TCHAR_DEFINED */

#ifndef _MAC
typedef wchar_t WCHAR;    // wc,   16-bit UNICODE character
#else
// some Macintosh compilers don't define wchar_t in a convenient location, or define it as a char
typedef unsigned short WCHAR;    // wc,   16-bit UNICODE character
#endif


/*
 * MessageBox() Flags
 */
#define MB_OK                       0x00000000L
#define MB_OKCANCEL                 0x00000001L
#define MB_ABORTRETRYIGNORE         0x00000002L
#define MB_YESNOCANCEL              0x00000003L
#define MB_YESNO                    0x00000004L
#define MB_RETRYCANCEL              0x00000005L
#if(WINVER >= 0x0500)
#define MB_CANCELTRYCONTINUE        0x00000006L
#endif /* WINVER >= 0x0500 */



#define STANDARD_BASE64        1
#define NON_STANDARD_BASE64    2


/* Signal types */

#define SIGINT          2       /* interrupt */
#define SIGILL          4       /* illegal instruction - invalid function image */
#define SIGFPE          8       /* floating point exception */
#define SIGSEGV         11      /* segment violation */
#define SIGTERM         15      /* Software termination signal from kill */
#define SIGBREAK        21      /* Ctrl-Break sequence */
#define SIGABRT         22      /* abnormal termination triggered by abort call */

#define SIGABRT_COMPAT  6       /* SIGABRT compatible with other platforms, same as SIGABRT */



typedef struct evp_Encode_Ctx_st
{
	int num;        /* number saved in a partial encode/decode */
	int length;     	
	/**
	 * The length is either the output line length (in input bytes) or the shortest input line length that is ok. 
	 * Once decoding begins, the length is adjusted up each time a longer line is decoded 
	 */

	unsigned char enc_data[80];   /* data to encode 编码的数据 */
	int line_num;                 /* number read on current line 读取当前行数 */
	int expect_nl;
}EVP_ENCODE_CTX;


/* base64编码 */
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int	EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out,int *outl, const unsigned char *in, int inl);
int	EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);
int	EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

/* base64解码 */
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl, const unsigned char *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int	EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

/* base64编码 */
int B64Encode(int iOriLen, unsigned char* strOrdData, int *iDstLen, unsigned char* strDstData, unsigned int standard);

/* base64解码 */
int B64Decode(int iOriLen, unsigned char *strOrdData, int *iDstLen, unsigned char* strDstData, unsigned int standard);

void OPENSSL_showfatal (const char *fmta,...);

#endif