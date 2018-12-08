namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 4492 5.1.2
	/// </summary>
	public class ECPointFormat
	{
		public const short uncompressed = 0;
		public const short ansiX962_compressed_prime = 1;
		public const short ansiX962_compressed_char2 = 2;

		/*
		 * reserved (248..255)
		 */
	}

}