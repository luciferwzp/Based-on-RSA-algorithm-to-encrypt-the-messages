#include"RSA.h"
#include<time.h>
#include<iostream>
#include<fstream>

void RSA::ecrept(const char* plain_file_in, const char* ecrept_file_out,
        bm::int1024_t ekey, bm::int1024_t pkey)//对信息进行加密
{
    std::ifstream file_in(plain_file_in);
    std::ofstream file_out(ecrept_file_out, std::ofstream::app);
    if (!file_in.is_open())
    {
        std::cout << "open file error!!!" << std::endl;
        return;
    }
    //定一个长度,按长度加密
    const int num =  1024;
    char buffer[num];
    bm::int1024_t buffer_out[num];
    int cur_num;
    while (!file_in.eof())
    {
        file_in.read(buffer, num);
        cur_num = file_in.gcount();//返回读取的字节数
        for (int i = 0; i < cur_num; ++i)
        {
            buffer_out[i] = ecrept((bm::int1024_t)buffer[i], ekey, pkey);
        }
        file_out.write((char*)buffer_out, cur_num * sizeof(bm::int1024_t));
    }
    file_in.close();
    file_out.close();
}

void RSA::decrept(const char* ecrept_file_in, const char* plain_file_out,
        bm::int1024_t dkey, bm::int1024_t pkey)//对信息进行解密
{
    std::ifstream file_in(ecrept_file_in);
    std::ofstream file_out(plain_file_out);
    if (!file_in.is_open())
    {
        std::cout << "open file error!!!" << std::endl;
        return;
    }

    const int num = 50;
    bm::int1024_t buffer[num];
    char buffer_out[num];
    int cur_num;
    while (!file_in.eof())
    {
        //打开解密文件，按块读取解密
        file_in.read((char*)buffer, num * sizeof(bm::int1024_t));
        cur_num = file_in.gcount();//返回读取字节数
        cur_num /= sizeof(bm::int1024_t);
        for (int i = 0; i < cur_num; ++i)
        {
            buffer_out[i] =(char)ecrept(buffer[i], dkey, pkey);
        }
        file_out.write(buffer_out, cur_num);
    }
    file_in.close();
    file_out.close();
}

std::vector<bm::int1024_t> RSA::ecrept(std::string& str_in, bm::int1024_t ekey, bm::int1024_t pkey)//对字符串加密
{
    std::vector<bm::int1024_t> vec_out;
    for (const auto& e : str_in)
    {
        vec_out.push_back(ecrept(e, ekey, pkey));//将加密的信息放入到vec_out中
    }
    return vec_out;
}

std::string RSA::decrept(std::vector<bm::int1024_t>& ecrept_str, bm::int1024_t dkey, bm::int1024_t pkey)//对加密的字符串解密
{
    std::string str_out;
    for (const auto& e : ecrept_str)
    {
        str_out.push_back((char)ecrept(e, dkey, pkey));//将解密的字符放入到str_out中
    }
    return str_out;
}

bm::int1024_t RSA::ecrept(bm::int1024_t mg, bm::int1024_t ekey, bm::int1024_t pkey)//加密   mg：需要加密的信息
{
    bm::int1024_t mg_out = 1;
    bm::int1024_t a = mg;
    bm::int1024_t b = ekey;
    bm::int1024_t c = pkey;
    while (b)
    {
        if (b & 1)
        {
            mg_out = (mg_out * a) % c;
        }
        b >> 1;
        a = (a * a) % c;
    }
    return mg_out;
}

bm::int1024_t RSA::produce_prime()//产生素数
{
    srand(time(nullptr));
    bm::int1024_t prime = 0;
    while (1)
    {
        prime = rand() % 20 + 2;//产生一个大于2的素数
        if (is_prime(prime))
        {
            break;
        }
    }
    return prime;
}

bool RSA::is_prime(bm::int1024_t prime)//判断是否为素数
{
    if (prime < 2)
    {
        return false;
    }
    for(int i = 2; i <= sqrt(prime); i++)
    {
        if (prime % i == 0)
        {
            return false;
        }
    }
    return true;
}

void RSA::produce_keys()//存放公钥秘钥
{
    bm::int1024_t prime1 = produce_prime();
    bm::int1024_t prime2 = produce_prime();
    while (prime1 == prime2)//两个素数不能相同
    {
        prime2 = produce_prime();
    }

    _key.pkey = produce_pkey(prime1, prime2);//p*q
    bm::int1024_t orla = produce_orla(prime1, prime2);//(p-1)*(q-1)
    _key.ekey = produce_ekey(orla);//公钥
    _key.dkey = produce_dkey(_key.ekey, orla);//秘钥

}

bm::int1024_t RSA::produce_pkey(bm::int1024_t prime1, bm::int1024_t prime2)//pq->n
{
    return prime1 * prime2;
}

bm::int1024_t RSA::produce_orla(bm::int1024_t prime1, bm::int1024_t prime2)//(p-1)(q-1)
{
    return (prime1 - 1) * (prime2 - 1);

}

bm::int1024_t RSA::produce_ekey(bm::int1024_t orla)//产生公钥
{
    bm::int1024_t ekey;
    srand(time(nullptr));
    while (1)
    {
        ekey = rand() % orla;
        if (ekey > 1 && produce_gcd(ekey, orla) == 1)
        {
            break;
        }
    }
    return ekey;

}

bm::int1024_t RSA::produce_gcd(bm::int1024_t ekey, bm::int1024_t orla)//公钥要和oral互质
{
    bm::int1024_t residual;           //residual:余数
    while (residual = ekey % orla)
    {
        ekey = orla;
        orla = residual;
    }
    return orla;
}

bm::int1024_t RSA::produce_dkey(bm::int1024_t ekey, bm::int1024_t orla)//产生秘钥
{
    bm::int1024_t dkey = orla / ekey;
    while (1)
    {
        if ((dkey * ekey) % orla == 1)
        {
            break;
        }
        ++dkey;
    }
    return dkey;
}

void RSA::printInfo(std::vector<bm::int1024_t>& ecrept_str)
{
    for (const auto& e : ecrept_str)
    {
        std::cout << e << "@";
    }
    std::cout << std::endl;
}


