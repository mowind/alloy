
#ifndef _SM2_SIGN_H_
#define _SM2_SIGN_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
## SM2 C接口

### 生成公私钥 sm2_genKey
*/
int sm2_genKey(unsigned char *privkey, unsigned char *pubkey);
/*
* 输入参数：

rand: 随机数

        * 返回值：

函数返回值为0时，代表生成成功。其他非0返回值可以区分错误信息。

privkey：返回的私钥

pubkey：返回的公钥

 */
/*
### 签名 sm2_sign
*/
int sm2_sign(unsigned char *sig, const unsigned char *hash, const unsigned char *seckey);
/*
用私钥对信息进行SM2签名，签名结果，包含r，s，v三个值。

* 输入参数：

msg32：需要签名的32字节数据。

seckey：签名用的私钥。

* 返回值：

函数返回值为0时，代表签名成功。其他非0返回值可以区分错误信息。

sig：成功的情况下，返回65字节的签名数据。r 32字节，s 32字节，v 1个字节。
*/
/*
### 恢复公钥 sm2_recover_pubkey
*/
int sm2_recover_pubkey(unsigned char *pubkey, const unsigned char *hash, const unsigned char *sig);
/*
用sm2签名和信息，恢复出公钥。

* 输入参数：

msg32：签名的信息

        sig：签名值，65字节的签名数据，包含r，s，v

        * 返回值：

函数返回值为0时，代表调用成功。其他非0返回值可以区分错误信息。

pubkey：成功的话，返回公钥数组。
*/
/*
### 验证签名 sm2_verify_signature
*/
int sm2_verify_signature(const unsigned char *pubkey, const unsigned char *hash, const unsigned char *sig);
/*
验证sm2签名。

* 输入参数：

pubkey：签名者公钥

        msg32：签名的信息

        sig：64字节签名数据，包含r，s。不包含v。

* 返回值：

验证签名成功函数返回0。其他非0返回值可以区分错误信息。
*/

/*
### 解压公钥 sm2_decompress_pubkey
*/

int sm2_decompress_pubkey(unsigned char *outPubkey, const unsigned char *pubkey);
/*
* 输入参数：

pubkey：输入33字节的压缩公钥

        * 返回值：

解压成功函数返回值为0。其他非0返回值可以区分错误信息。

outPubkey：返回解压的公钥，数组前面是x坐标，后面是y坐标。
*/
/*
### 压缩公钥 sm2_compress_pubkey
*/

int sm2_compress_pubkey(unsigned char *pubkey, const unsigned char *x, const unsigned char *y);
/*
把x和y坐标表示的公钥压缩成33字节的公钥数组。

- 输入参数：

x：公钥x坐标

        y：公钥y坐标

- 返回值：

压缩成功返回0。其他非0返回值可以区分错误信息。

pubkey：压缩后的33字节公钥。
*/

int hash_ZA(unsigned char *ZA, const unsigned char *ID, unsigned int ID_len, const unsigned char *pubkey);

int sm2_scalar_mult(unsigned char *res, const unsigned char *g, const unsigned char *k);

int sm2_point_add(unsigned char *res, const unsigned char * p, const unsigned char * q);

int hash_to_curve(unsigned char *res, const unsigned char* in, int ilen);

#ifdef __cplusplus
}
#endif

#endif