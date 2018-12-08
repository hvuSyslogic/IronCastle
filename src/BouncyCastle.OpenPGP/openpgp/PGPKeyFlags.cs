namespace org.bouncycastle.openpgp
{
	/// <summary>
	/// key flag values for the KeyFlags subpacket.
	/// </summary>
	public interface PGPKeyFlags
	{
	}

	public static class PGPKeyFlags_Fields
	{
		public const int CAN_CERTIFY = 0x01;
		public const int CAN_SIGN = 0x02;
		public const int CAN_ENCRYPT_COMMS = 0x04;
		public const int CAN_ENCRYPT_STORAGE = 0x08;
		public const int MAYBE_SPLIT = 0x10;
		public const int CAN_AUTHENTICATE = 0x20;
		public const int MAYBE_SHARED = 0x80;
	}

}