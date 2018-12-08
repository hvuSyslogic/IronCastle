namespace org.bouncycastle.iana
{
	/// <summary>
	/// RFC 5116 
	/// </summary>
	public class AEADAlgorithm
	{
		public const int AEAD_AES_128_GCM = 1;
		public const int AEAD_AES_256_GCM = 2;
		public const int AEAD_AES_128_CCM = 3;
		public const int AEAD_AES_256_CCM = 4;

		/*
		 * RFC 5282
		 */
		public const int AEAD_AES_128_GCM_8 = 5;
		public const int AEAD_AES_256_GCM_8 = 6;
		public const int AEAD_AES_128_GCM_12 = 7;
		public const int AEAD_AES_256_GCM_12 = 8;
		public const int AEAD_AES_128_CCM_SHORT = 9;
		public const int AEAD_AES_256_CCM_SHORT = 10;
		public const int AEAD_AES_128_CCM_SHORT_8 = 11;
		public const int AEAD_AES_256_CCM_SHORT_8 = 12;
		public const int AEAD_AES_128_CCM_SHORT_12 = 13;
		public const int AEAD_AES_256_CCM_SHORT_12 = 14;

		/*
		 * RFC 5297
		 */
		public const int AEAD_AES_SIV_CMAC_256 = 15;
		public const int AEAD_AES_SIV_CMAC_384 = 16;
		public const int AEAD_AES_SIV_CMAC_512 = 17;

		/*
		 * RFC 6655
		 */
		public const int AEAD_AES_128_CCM_8 = 18;
		public const int AEAD_AES_256_CCM_8 = 19;

		/*
		 * RFC 7253
		 */
		public const int AEAD_AES_128_OCB_TAGLEN128 = 20;
		public const int AEAD_AES_128_OCB_TAGLEN96 = 21;
		public const int AEAD_AES_128_OCB_TAGLEN64 = 22;
		public const int AEAD_AES_192_OCB_TAGLEN128 = 23;
		public const int AEAD_AES_192_OCB_TAGLEN96 = 24;
		public const int AEAD_AES_192_OCB_TAGLEN64 = 25;
		public const int AEAD_AES_256_OCB_TAGLEN128 = 26;
		public const int AEAD_AES_256_OCB_TAGLEN96 = 27;
		public const int AEAD_AES_256_OCB_TAGLEN64 = 28;

		/*
		 * RFC 7539
		 */
		public const int AEAD_CHACHA20_POLY1305 = 29;
	}

}