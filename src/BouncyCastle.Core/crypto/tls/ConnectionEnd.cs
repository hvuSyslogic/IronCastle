namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 2246
	/// <para>
	/// Note that the values here are implementation-specific and arbitrary. It is recommended not to
	/// depend on the particular values (e.g. serialization).
	/// </para>
	/// </summary>
	public class ConnectionEnd
	{
		public const int server = 0;
		public const int client = 1;
	}

}