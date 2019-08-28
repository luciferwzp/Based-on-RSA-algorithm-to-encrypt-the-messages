# Based-on-RSA-algorithm-to-encrypt-the-file
基于RSA算法对信息进行加密

1.RSA的命名由来
    1977年，由三位数学家Rivest、Shamir和Adleman设计了一种算法，此算法实现非对称加密。因此这种算法就由他们三人的名字命名，叫做RSA算法。
    
2.RSA加密公式  

  加密：公钥(E，N)  
                    密 文 = (明 文)^E mod N
  解密：密钥(D，N)  
                    明 文 = (密 文)^E mod N
    
    RSA的安全主要于大数分解的难度。其公钥是一对大素数(100到200或者更大)的函数。从知道一个公钥和密文翻译出明文的难度，等价于分解了两个大素数之积。

3.
