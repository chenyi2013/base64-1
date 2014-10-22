####  base64加解码过程

    移植的代码开头ts_

base64
Base64是网络上最常见的用于传输8Bit字节代码的编码方式之一。Base64编码可用于在HTTP环境下传递较长的标识信息。例如，在Java Persistence系统Hibernate中，就采用了Base64来将一个较长的唯一标识符（一般为128-bit的UUID）编码为一个字符串，用作HTTP表单和HTTP GET URL中的参数。在其他应用程序中，也常常需要把二进制数据编码为适合放在URL（包括隐藏表单域）中的形式。此时，采用Base64编码具有不可读性，即所编码的数据不会被人用肉眼所直接看到。

简介
Base64要求把每三个8Bit的字节转换为四个6Bit的字节（3*8 = 4*6 = 24），然后把6Bit再添两位高位0，组成四个8Bit的字节，也就是说，转换后的字符串理论上将要比原来的长1/3。

规则
关于这个编码的规则：
1、把3个字符变成4个字符。
2、每76个字符加一个换行符。
3、最后的结束符也要处理。
例1:
转换前 11111111, 11111111, 11111111 （二进制）
转换后 00111111, 00111111, 00111111, 00111111 （二进制）
上面的三个字节是原文，下面的四个字节是转换后的Base64编码，其前两位均为0。
转换后，我们用一个码表来得到我们想要的字符串（也就是最终的Base64编码），这个表是这样的(摘自RFC2045)



例2:
转换前 10101101、10111010、01110110
转换后 00101011、 00011011 、00101001 、00110110
十进制 43 27 41 54
对应码表中的值 r b p 2
所以上面的24位编码，编码后的Base64值为 rbp2
解码同理，把 rbq2 的二进制位连接上再重组得到三个8位值，得出原码。
（解码只是编码的逆过程，有关MIME的RFC还有很多，如果需要详细情况请自行查找。）


##  Openssl中用于base64编码的函数主要有:

####  EVP_EncodeInit函数

    void EVP_EncodeInit(EVP_ENCODE_CTX *ctx)
  
  功能：该函数初始化一个用来进行base64编码的结构，事实上，该函数只是简单设置了结构里面几个常量的长度。
  参数： ctx：base64设备上下文。 


####  EVP_EncodeUpdate函数
   
    void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl, 
                          const unsigned char *in, int inl)
  
  功能：该函数将参数in里面的inl自己数据拷贝到结构体ctx里面，如果结构体里面有数据，就同时将结构体里面的数据进行BASE64编码并输出到参数out指向的缓存里面，输出数据的长度保存在outl里面。注意，在第一次调用本函数的时候，虽然往结构体里面拷贝数据了，但是结构体ctx里面开始是没有输入数据存在并且输入数据长度不超出ctx内部存储数据的最长限制，就不会有任何数据被进行BASE64编码，也就是说，不会有任何数据输出；但是如果输入数据长度比内部存储的数据长，那么就会输出部分经过BASE64编码的数据。数据输出总是在下一层输入前完成的。

参数：

    ctx : base64设备上下文;  out: 存放编码后的数据缓冲区;  
    outl: 编码后的数据长度;  in : 编码前数据;  inl: 编码前的数据长度。


####  EVP_EncodeFinal函数

    void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)

  功能：该函数将结构体ctx里面剩余数据进行BASE64编码并写入到参数out里面去，输出数据的长度保存在outl里面。

  参数：

    ctx: base64设备上下文;   out: 存放编码后的数据;   outl: 编码后的数据长度。

####  EVP_EncodeBlock函数

    int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);

  功能:该函数将参数f里面的字符串里面的n个字节的字符串进行BASE64编码并输出到参数t里面。返回数据的字节长度。
  事实上，在函数 EVP_EncodeUpdate 和 EVP_EncodeFinal 里面就调用了该函数完成 BASE64 编码功能。

  参数：
  t：接收编码后的数据缓冲区。
  f：编码前的数据。
  n：编码前的数据长度。






####  openssl之EVP系列之15---EVP_Decode系列函数介绍 

  本系列函数与EVP_Encode系列函数相对，对数据进行BASE64解码,其定义的函数如下(openssl\evp.h):

    void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);

    int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,
                         int *outl,unsigned char *in, int inl);

    int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl);

    int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);

EVP_DecodeInit  --> 该函数初始化一个用来进行BASE64解码的数据结构。
参数： ctx：base64设备上下文。

####  EVP_DecodeUpdate

    int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, unsigned char *out, 
                         int *outl, const unsigned char *in, int inl)

  功能: 该函数将参数in里面inl字节的数据拷贝到结构体ctx里面。如果结构体里面已经有数据，那么这些数据就会先进行BASE64解码，然后输出到参数out指向的内存中，输出的字节数保存在参数outl里面。输入数据为满行的数据时，返回为1；如果输入数据是最后一行数据的时候，返回0；返回－1则表明出错了。

  参数：p
    ctx  ：base64设备上下文。
    out  ：存放解码后的数据缓冲区。
    outl ：解码后的数据长度。
    in   ：解码前的数据。
    inl  ：解码前的数据长度

####  EVP_DecodeFinal

    int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned char *out, int *outl)

  功能：该函数将结构体ctx里面剩余的数据进行BASE64解码并输出到参数out指向的内存中，输出数据长度为outl字节。成功返回1，否则返回－1。

  参数：

    ctx ：base64设备上下文。
    out ：解码后的数据。
    outl：解码后的数据长度。

####  EVP_DecodeBlock

    int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n)

  功能：该函数将字符串f中的n字节数据进行BASE64解码，并输出到t指向的内存中，输出数据长度为outl。成功返回解码的数据长度，返回返回－1。

  参数：
  
    t：接收解码后的数据缓冲区。
    f：解码前的数据。
    n：解码前的数据长度。






 

http://wenku.baidu.com/link?url=UZ0pimBeKjsB61LJDLgO_9GP42XD5m0u6JJmjQasfAipGhlPmhQcBN1My22XR5YUVmUVt7d-8gndJD4Cky2Hxub36z7Xkt2SJiO2qS2gvoK




















