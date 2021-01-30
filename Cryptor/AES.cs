using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Cryptor
{
    public class AES
    {
        /// <summary>
        /// AES256 암호화
        /// </summary>
        /// <param name="text">평문</param>
        /// <param name="key">암호화할 키 값</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string Encrypt(string text, string key, Encoding encoding)
        {
            try
            {
                byte[] textData = encoding.GetBytes(text);
                byte[] salt = Encoding.ASCII.GetBytes(key.Length.ToString());
                var secretKey = new PasswordDeriveBytes(key, salt);

                var aes = new RijndaelManaged();
                ICryptoTransform encryptor = aes.CreateEncryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));

                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(textData, 0, textData.Length);
                    cs.FlushFinalBlock();
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                return "Encrypt error : " + e.Message;
            }
        }

        /// <summary>
        /// AES256 복호화
        /// </summary>
        /// <param name="encryptText">암호화된 문자열</param>
        /// <param name="key">복호화할 키 값</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 복호화한 문자열</returns>
        public static string Decrypt(string encryptText, string key, Encoding encoding)
        {
            try
            {
                byte[] encryptData = Convert.FromBase64String(encryptText);
                byte[] salt = Encoding.ASCII.GetBytes(key.Length.ToString());
                var secretKey = new PasswordDeriveBytes(key, salt);

                var aes = new RijndaelManaged();
                ICryptoTransform decryptor = aes.CreateDecryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));

                using (var ms = new MemoryStream())
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    byte[] result = new byte[encryptData.Length];
                    int decryptedCount = cs.Read(result, 0, result.Length);
                    return encoding.GetString(result, 0, decryptedCount);
                }
            }
            catch (Exception e)
            {
                return "Decrypt error : " + e.Message;
            }
        }

    }
}