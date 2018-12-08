namespace org.bouncycastle.crypto.tls
{
	/*
	 * draft-ietf-tls-negotiated-ff-dhe-01
	 */
	public class FiniteFieldDHEGroup
	{
		public const short ffdhe2432 = 0;
		public const short ffdhe3072 = 1;
		public const short ffdhe4096 = 2;
		public const short ffdhe6144 = 3;
		public const short ffdhe8192 = 4;

		public static bool isValid(short group)
		{
			return group >= ffdhe2432 && group <= ffdhe8192;
		}
	}

}