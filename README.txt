C# 암/복호화 DLL
개발 툴 : Microsoft Visual Studio 17
대상 프레임워크 : .NET Framework 4.5

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
			// MD5
			string text = "Plan text for hash test.";
			string hash = Hash.EncryptMD5(text, Encoding.Unicode);
			bool isSame = Hash.IsSameHash(text, hash, Hash.HashType.MD5, Encoding.Unicode);
			Console.WriteLine(isSame); // Output : true

			// SHA256
			string text = "Plan text for hash test.";
			string hash = Hash.EncryptSHA256(text, Encoding.Unicode);
			bool isSame = Hash.IsSameHash(text, hash, Hash.HashType.SHA256, Encoding.Unicode);
			Console.WriteLine(isSame); // Output : true

			// SHA384
			string text = "Plan text for hash test.";
			string hash = Hash.EncryptSHA384(text, Encoding.Unicode);
			bool isSame = Hash.IsSameHash(text, hash, Hash.HashType.SHA384, Encoding.Unicode);
			Console.WriteLine(isSame); // Output : true

			// SHA512
			string text = "Plan text for hash test.";
			string hash = Hash.EncryptSHA512(text, Encoding.Unicode);
			bool isSame = Hash.IsSameHash(text, hash, Hash.HashType.SHA512, Encoding.Unicode);
			Console.WriteLine(isSame); // Output : true

  2) AES 암/복호화
			// AES
			string text = "Plan text for aes test.";
			string key = "Plan text for aes test.";
			string encrypted = AES.Encrypt(text, key, Encoding.Unicode);
			Console.WriteLine(encrypted);

			string decrypted = AES.Decrypt(encrypted, key, Encoding.Unicode);
			Console.WriteLine(decrypted);

			bool isSame = text == decrypted;
			Console.WriteLine(isSame); // Output : true
