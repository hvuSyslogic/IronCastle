namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// Basic PGP signature sub-packet tag types.
	/// </summary>
	public interface SignatureSubpacketTags
	{
	}

	public static class SignatureSubpacketTags_Fields
	{
		public const int CREATION_TIME = 2;
		public const int EXPIRE_TIME = 3;
		public const int EXPORTABLE = 4;
		public const int TRUST_SIG = 5;
		public const int REG_EXP = 6;
		public const int REVOCABLE = 7;
		public const int KEY_EXPIRE_TIME = 9;
		public const int PLACEHOLDER = 10;
		public const int PREFERRED_SYM_ALGS = 11;
		public const int REVOCATION_KEY = 12;
		public const int ISSUER_KEY_ID = 16;
		public const int NOTATION_DATA = 20;
		public const int PREFERRED_HASH_ALGS = 21;
		public const int PREFERRED_COMP_ALGS = 22;
		public const int KEY_SERVER_PREFS = 23;
		public const int PREFERRED_KEY_SERV = 24;
		public const int PRIMARY_USER_ID = 25;
		public const int POLICY_URL = 26;
		public const int KEY_FLAGS = 27;
		public const int SIGNER_USER_ID = 28;
		public const int REVOCATION_REASON = 29;
		public const int FEATURES = 30;
		public const int SIGNATURE_TARGET = 31;
		public const int EMBEDDED_SIGNATURE = 32;
	}

}