#pragma once
#include<iostream>
#include <string>
#include <vector>
#include<stdlib.h>
#include<time.h>
#include<math.h>
#include<fstream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/random.hpp>
namespace bm = boost::multiprecision;

struct Key
{
	//公钥(ekey, pkey): (e, n)
	bm::int1024_t pkey;
	bm::int1024_t ekey;
	//私钥(dkey, pkey): (d, n)
	bm::int1024_t dkey;
};

class RSA
{
public:
	RSA() {};
	Key getKey()
	{
		return _key;
	}
	
	void ecrept(const char* plain_file_in, const char* ecrept_file_out,
		bm::int1024_t ekey, bm::int1024_t pkey);//对文件进行解密
	void decrept(const char* ecrept_file_in, const char* plain_file_out,
		bm::int1024_t dkey, bm::int1024_t pkey);//对文件进行加密

	std::vector<bm::int1024_t> ecrept(std::string& str_in, bm::int1024_t ekey, bm::int1024_t pkey);//对字符串进行加密
	std::string decrept(std::vector<bm::int1024_t>& ecrept_str, bm::int1024_t dkey, bm::int1024_t pkey);//对字符串进行解密	

	void printInfo(std::vector<bm::int1024_t>& ecrept_str);//打印解密后的信息
private:
	//加密单个信息
	bm::int1024_t ecrept(bm::int1024_t msg, bm::int1024_t ekey, bm::int1024_t pkey);//加密
	bm::int1024_t produce_prime();//产生素数
	bool is_prime(bm::int1024_t prime);//判断是否为素数
	void produce_keys();//存放公钥秘钥
	bm::int1024_t produce_pkey(bm::int1024_t prime1, bm::int1024_t prime2);//pq->n
	bm::int1024_t produce_orla(bm::int1024_t prime1, bm::int1024_t prime2);//(p-1)(q-1)
	bm::int1024_t produce_ekey(bm::int1024_t orla);//产生公钥
	bm::int1024_t produce_gcd(bm::int1024_t ekey, bm::int1024_t orla);//互质
	bm::int1024_t produce_dkey(bm::int1024_t ekey, bm::int1024_t orla);//产生秘钥

private:
	Key _key;
};
