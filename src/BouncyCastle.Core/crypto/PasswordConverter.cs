namespace org.bouncycastle.crypto
{
    /// <summary>
    /// Standard char[] to byte[] converters for password based derivation algorithms.
    /// </summary>
    public sealed class PasswordConverter
    {
        /// <summary>
        /// Do a straight char[] to 8 bit conversion.
        /// </summary>
        public static readonly CharToByteConverter ASCII = new CharToByteConverterAnonymousInnerClass();

        public class CharToByteConverterAnonymousInnerClass : CharToByteConverter
        {
            public string getType()
            {
                return "ASCII";
            }

            public byte[] convert(char[] password)
            {
                return PBEParametersGenerator.PKCS5PasswordToBytes(password);
            }
        }

        /// <summary>
        /// Do a char[] conversion by producing UTF-8 data.
        /// </summary>
        public static readonly CharToByteConverter UTF8 = new CharToByteConverterAnonymousInnerClass2();

        public class CharToByteConverterAnonymousInnerClass2 : CharToByteConverter
        {
            public string getType()
            {
                return "UTF8";
            }

            public byte[] convert(char[] password)
            {
                return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
            }
        }

        /// <summary>
        /// Do char[] to BMP conversion (i.e. 2 bytes per character).
        /// </summary>
        public static readonly CharToByteConverter PKCS12 = new CharToByteConverterAnonymousInnerClass3();

        public class CharToByteConverterAnonymousInnerClass3 : CharToByteConverter
        {
            public string getType()
            {
                return "PKCS12";
            }

            public byte[] convert(char[] password)
            {
                return PBEParametersGenerator.PKCS12PasswordToBytes(password);
            }
        }
    }
}
