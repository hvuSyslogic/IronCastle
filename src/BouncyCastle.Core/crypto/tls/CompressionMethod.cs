namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 2246 6.1
	/// </summary>
	public class CompressionMethod
	{
		public const short _null = 0;

		/*
		 * RFC 3749 2
		 */
		public const short DEFLATE = 1;

		/*
		 * Values from 224 decimal (0xE0) through 255 decimal (0xFF)
		 * inclusive are reserved for private use.
		 */
	}

}