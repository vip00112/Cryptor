C# 암/복호화 DLL
개발 툴 : Microsoft Visual Studio 15
대상 프레임워크 : .NET Framework 4 Client Profile

1. 구분
 1) Hash
   - MD5 암호화
   - SHA256 암호화
   - SHA384 암호화
   - SHA512 암호화
   - Hash값 비교
 2) AES
   - AES256 암/복호화

2. 사용 예제
  1) Hash 암호화 및 비교
    string text = "Test text for SHA512";
    string hash = Cryptor.Hash.encryptSHA512(text);
    bool isSameHash = Cryptor.Hash.isSameHash(text, hash, "SHA512");
    Console.WriteLine(isSameHash); // 출력 : True

  2) AES 암/복호화
    string text = "Test text for AES256";
    string key  = "Test key for AES256";
    string encText = Cryptor.AES.encryptAES256(text, key);
    string decText = Cryptor.AES.decryptAES256(encText, key);
    bool isSameText = text == decText;
    Console.WriteLine(isSameText); // 출력 : True