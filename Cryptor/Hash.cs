using System;
using System.Security.Cryptography;
using System.Text;

namespace Cryptor
{
    public class Hash
    {
        public enum HashType { MD5, SHA256, SHA384, SHA512 }

        /// <summary>
        /// MD5 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string EncryptMD5(string text, Encoding encoding)
        {
            var md5 = System.Security.Cryptography.MD5.Create();
            byte[] data = md5.ComputeHash(encoding.GetBytes(text));

            var sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA256 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string EncryptSHA256(string text, Encoding encoding)
        {
            var sha = new System.Security.Cryptography.SHA256Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            var sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA384 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string EncryptSHA384(string text, Encoding encoding)
        {
            var sha = new System.Security.Cryptography.SHA384Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            var sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// SHA512 암호화
        /// </summary>
        /// <param name="text">암호화 할 평문</param>
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>지정된 인코딩으로 암호화한 문자열</returns>
        public static string EncryptSHA512(string text, Encoding encoding)
        {
            var sha = new System.Security.Cryptography.SHA512Managed();
            byte[] data = sha.ComputeHash(encoding.GetBytes(text));

            var sb = new StringBuilder();
            foreach (byte b in data)
            {
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
        /// <param name="encoding">System.Text.Encoding</param>
        /// <returns>평문을 지정된 인코딩으로 암호화한 후 비교 결과 True/False</returns>
        public static bool IsSameHash(string text, string oldHash, HashType type, Encoding encoding)
        {
            string newHash = null;
            switch (type)
            {
                case HashType.MD5:
                    newHash = EncryptMD5(text, encoding);
                    break;
                case HashType.SHA256:
                    newHash = EncryptSHA256(text, encoding);
                    break;
                case HashType.SHA384:
                    newHash = EncryptSHA384(text, encoding);
                    break;
                case HashType.SHA512:
                    newHash = EncryptSHA512(text, encoding);
                    break;
                default:
                    return false;
            }
            var comparer = StringComparer.OrdinalIgnoreCase;
            return comparer.Compare(newHash, oldHash) == 0;
        }
    }
}