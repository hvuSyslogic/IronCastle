namespace org.bouncycastle.crypto.tls
{
	public class NameType
	{
		/*
		 * RFC 3546 3.1.
		 */
		public const short host_name = 0;

		public static bool isValid(short nameType)
		{
			return nameType == host_name;
		}
	}

}