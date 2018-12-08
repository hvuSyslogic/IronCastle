namespace org.bouncycastle.bcpg
{
	/// <summary>
	/// Basic PGP packet tag types.
	/// </summary>
	public interface PacketTags
	{
	}

	public static class PacketTags_Fields
	{
		  public const int RESERVED = 0;
		  public const int PUBLIC_KEY_ENC_SESSION = 1;
		  public const int SIGNATURE = 2;
		  public const int SYMMETRIC_KEY_ENC_SESSION = 3;
		  public const int ONE_PASS_SIGNATURE = 4;
		  public const int SECRET_KEY = 5;
		  public const int PUBLIC_KEY = 6;
		  public const int SECRET_SUBKEY = 7;
		  public const int COMPRESSED_DATA = 8;
		  public const int SYMMETRIC_KEY_ENC = 9;
		  public const int MARKER = 10;
		  public const int LITERAL_DATA = 11;
		  public const int TRUST = 12;
		  public const int USER_ID = 13;
		  public const int PUBLIC_SUBKEY = 14;
		  public const int USER_ATTRIBUTE = 17;
		  public const int SYM_ENC_INTEGRITY_PRO = 18;
		  public const int MOD_DETECTION_CODE = 19;
		  public const int EXPERIMENTAL_1 = 60;
		  public const int EXPERIMENTAL_2 = 61;
		  public const int EXPERIMENTAL_3 = 62;
		  public const int EXPERIMENTAL_4 = 63;
	}

}