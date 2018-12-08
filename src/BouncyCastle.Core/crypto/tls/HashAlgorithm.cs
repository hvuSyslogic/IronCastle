namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 5246 7.4.1.4.1
	/// </summary>
	public class HashAlgorithm
	{
		public const short none = 0;
		public const short md5 = 1;
		public const short sha1 = 2;
		public const short sha224 = 3;
		public const short sha256 = 4;
		public const short sha384 = 5;
		public const short sha512 = 6;

		public static string getName(short hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case none:
				return "none";
			case md5:
				return "md5";
			case sha1:
				return "sha1";
			case sha224:
				return "sha224";
			case sha256:
				return "sha256";
			case sha384:
				return "sha384";
			case sha512:
				return "sha512";
			default:
				return "UNKNOWN";
			}
		}

		public static string getText(short hashAlgorithm)
		{
			return getName(hashAlgorithm) + "(" + hashAlgorithm + ")";
		}

		public static bool isPrivate(short hashAlgorithm)
		{
			return 224 <= hashAlgorithm && hashAlgorithm <= 255;
		}

		public static bool isRecognized(short hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case md5:
			case sha1:
			case sha224:
			case sha256:
			case sha384:
			case sha512:
				return true;
			default:
				return false;
			}
		}
	}

}