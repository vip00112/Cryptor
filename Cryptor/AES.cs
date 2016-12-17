using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Cryptor {
    public class AES {
        /// <summary>
        /// AES256 암호화
        /// </summary>
        /// <param name="text">평문</param>
        /// <param name="key">암호화할 키 값</param>
        /// <returns>Unicode 인코딩으로 암호화한 문자열</returns>
        public static string encryptAES256(string text, string key) {
            return encryptAES256(text, key, Encoding.Unicode);
        }

        /// <summary>
        /// AES256 암호화
        /// </summary>
        /// <param name="text">평문</param>
        /// <param name="key">암호화할 키 값</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string encryptAES256(string text, string key, Encoding encoding) {
            MemoryStream ms = null;
            CryptoStream cs = null;
            try {
                RijndaelManaged aes = new RijndaelManaged();

                byte[] textData = encoding.GetBytes(text);
                byte[] salt = Encoding.ASCII.GetBytes(key.Length.ToString());
                PasswordDeriveBytes secretKey = new PasswordDeriveBytes(key, salt);

                ICryptoTransform encryptor = aes.CreateEncryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));
                ms = new MemoryStream();
                cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

                cs.Write(textData, 0, textData.Length);
                cs.FlushFinalBlock();
                return Convert.ToBase64String(ms.ToArray());
            } catch (Exception e) {
                return "Encrypt ERROR : " + e.Message;
            } finally {
                if (cs != null) {
                    cs.Close();
                }
                if (ms != null) {
                    ms.Close();
                }
            }
        }

        /// <summary>
        /// AES256 복호화
        /// </summary>
        /// <param name="encryptText">암호화된 문자열</param>
        /// <param name="key">복호화할 키 값</param>
        /// <returns>Unicode 인코딩으로 복호화한 문자열</returns>
        public static string decryptAES256(string encryptText, string key) {
            return decryptAES256(encryptText, key, Encoding.Unicode);
        }

        /// <summary>
        /// AES256 복호화
        /// </summary>
        /// <param name="encryptText">암호화된 문자열</param>
        /// <param name="key">복호화할 키 값</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 복호화한 문자열</returns>
        public static string decryptAES256(string encryptText, string key, Encoding encoding) {
            MemoryStream ms = null;
            CryptoStream cs = null;
            try {
                RijndaelManaged aes = new RijndaelManaged();

                byte[] encryptData = Convert.FromBase64String(encryptText);
                byte[] salt = Encoding.ASCII.GetBytes(key.Length.ToString());
                PasswordDeriveBytes secretKey = new PasswordDeriveBytes(key, salt);

                ICryptoTransform decryptor = aes.CreateDecryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));
                ms = new MemoryStream(encryptData);
                cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                byte[] result = new byte[encryptData.Length];
                int decryptedCount = cs.Read(result, 0, result.Length);

                return encoding.GetString(result, 0, decryptedCount);
            } catch (Exception e) {
                return "Decrypt ERROR : " + e.Message;
            } finally {
                if (cs != null) {
                    cs.Close();
                }
                if (ms != null) {
                    ms.Close();
                }
            }
        }

    }
}