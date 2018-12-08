namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 2246 6.2.1
	/// </summary>
	public class ContentType
	{
		public const short change_cipher_spec = 20;
		public const short alert = 21;
		public const short handshake = 22;
		public const short application_data = 23;
		public const short heartbeat = 24;
	}

}