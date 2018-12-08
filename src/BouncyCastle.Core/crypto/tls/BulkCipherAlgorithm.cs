namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 2246
	/// <para>
	/// Note that the values here are implementation-specific and arbitrary. It is recommended not to
	/// depend on the particular values (e.g. serialization).
	/// </para>
	/// </summary>
	public class BulkCipherAlgorithm
	{
		public const int _null = 0;
		public const int rc4 = 1;
		public const int rc2 = 2;
		public const int des = 3;
		public const int _3des = 4;
		public const int des40 = 5;

		/*
		 * RFC 4346
		 */
		public const int aes = 6;
		public const int idea = 7;
	}

}