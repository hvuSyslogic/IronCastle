namespace org.bouncycastle.bcpg.sig
{
	public interface RevocationReasonTags
	{

		// 100-110 - Private Use
	}

	public static class RevocationReasonTags_Fields
	{
		public const byte NO_REASON = 0;
		public const byte KEY_SUPERSEDED = 1;
		public const byte KEY_COMPROMISED = 2;
		public const byte KEY_RETIRED = 3;
		public const byte USER_NO_LONGER_VALID = 32;
	}

}