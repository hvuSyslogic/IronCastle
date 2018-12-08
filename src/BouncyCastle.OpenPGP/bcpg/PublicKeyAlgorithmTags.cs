namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// Public Key Algorithm tag numbers
	/// </summary>
	public interface PublicKeyAlgorithmTags
	{
		/// @deprecated use ECDH 
	}

	public static class PublicKeyAlgorithmTags_Fields
	{
		public const int RSA_GENERAL = 1;
		public const int RSA_ENCRYPT = 2;
		public const int RSA_SIGN = 3;
		public const int ELGAMAL_ENCRYPT = 16;
		public const int DSA = 17;
		public const int EC = 18;
		public const int ECDH = 18;
		public const int ECDSA = 19;
		public const int ELGAMAL_GENERAL = 20;
		public const int DIFFIE_HELLMAN = 21;
		public const int EDDSA = 22;
		public const int EXPERIMENTAL_1 = 100;
		public const int EXPERIMENTAL_2 = 101;
		public const int EXPERIMENTAL_3 = 102;
		public const int EXPERIMENTAL_4 = 103;
		public const int EXPERIMENTAL_5 = 104;
		public const int EXPERIMENTAL_6 = 105;
		public const int EXPERIMENTAL_7 = 106;
		public const int EXPERIMENTAL_8 = 107;
		public const int EXPERIMENTAL_9 = 108;
		public const int EXPERIMENTAL_10 = 109;
		public const int EXPERIMENTAL_11 = 110;
	}

}