using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptor {
    public class Hash {
        /// <summary>
        /// MD5 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <returns>Unicode 인코딩으로 암호화한 문자열</returns>
        public static string encryptMD5(string text) {
            return encryptMD5(text, Encoding.Unicode);
        }

        /// <summary>
        /// MD5 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string encryptMD5(string text, Encoding encoding) {
            MD5 md5 = MD5.Create();
            byte[] data = md5.ComputeHash(encoding.GetBytes(text));

            StringBuilder sb = new StringBuilder();
            foreach (byte b in data) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA256 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <returns>Unicode 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA256(string text) {
            return encryptSHA256(text, Encoding.Unicode);
        }

        /// <summary>
        /// SHA256 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA256(string text, Encoding encoding) {
            SHA256 sha = new SHA256Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            StringBuilder sb = new StringBuilder();
            foreach (byte b in data) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA384 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <returns>Unicode 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA384(string text) {
            return encryptSHA384(text, Encoding.Unicode);
        }

        /// <summary>
        /// SHA384 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA384(string text, Encoding encoding) {
            SHA384 sha = new SHA384Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            StringBuilder sb = new StringBuilder();
            foreach (byte b in data) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA512 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <returns>Unicode 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA512(string text) {
            return encryptSHA512(text, Encoding.Unicode);
        }

        /// <summary>
        /// SHA512 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string encryptSHA512(string text, Encoding encoding) {
            SHA512 sha = new SHA512Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            StringBuilder sb = new StringBuilder();
            foreach (byte b in data) {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// 평문화 Hash 암호화 문자열 비교
        /// </summary>
        /// <param name="text">평문</param>
        /// <param name="oldHash">Hash 암호화 문자열</param>
        /// <param name="type">MD5, SHA256, SHA384, SHA512</param>
        /// <returns>평문을 Unicode 인코딩으로 암호화한 후 비교 결과 True/False</returns>
        public static bool isSameHash(string text, string oldHash, string type) {
            string newHash = encryptSHA512(text);
            switch (type.ToUpper()) {
                case "MD5":
                    newHash = encryptMD5(text, Encoding.Unicode);
                    break;
                case "SHA256":
                    newHash = encryptSHA256(text, Encoding.Unicode);
                    break;
                case "SHA384":
                    newHash = encryptSHA384(text, Encoding.Unicode);
                    break;
                case "SHA512":
                    newHash = encryptSHA512(text, Encoding.Unicode);
                    break;
            }
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            return comparer.Compare(newHash, oldHash) == 0;
        }

        /// <summary>
        /// 평문화 Hash 암호화 문자열 비교
        /// </summary>
        /// <param name="text">평문</param>
        /// <param name="oldHash">Hash 암호화 문자열</param>
        /// <param name="type">MD5, SHA256, SHA384, SHA512</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>평문을 지정된 인코딩으로 암호화한 후 비교 결과 True/False</returns>
        public static bool isSameHash(string text, string oldHash, string type, Encoding encoding) {
            string newHash = encryptSHA512(text);
            switch (type.ToUpper()) {
                case "MD5":
                    newHash = encryptMD5(text, encoding);
                    break;
                case "SHA256":
                    newHash = encryptSHA256(text, encoding);
                    break;
                case "SHA384":
                    newHash = encryptSHA384(text, encoding);
                    break;
                case "SHA512":
                    newHash = encryptSHA512(text, encoding);
                    break;
                default:
                    return false;
            }
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            return comparer.Compare(newHash, oldHash) == 0;
        }

    }
}