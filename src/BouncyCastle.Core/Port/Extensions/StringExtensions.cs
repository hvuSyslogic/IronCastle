using System;
using System.Text;

namespace BouncyCastle.Core.Port.Extensions
{
    public static class StringExtensions
    {
        public static byte[] getBytes(this string @string)
        {
            return Encoding.ASCII.GetBytes(@string);
        }

        public static string substring(this string input , int start)
        {
            throw new NotImplementedException();
        }
    }
}