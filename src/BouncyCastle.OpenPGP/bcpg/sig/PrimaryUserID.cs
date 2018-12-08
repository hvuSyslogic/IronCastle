namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving whether or not the signature is signed using the primary user ID for the key.
	/// </summary>
	public class PrimaryUserID : SignatureSubpacket
	{
		private static byte[] booleanToByteArray(bool value)
		{
			byte[] data = new byte[1];

			if (value)
			{
				data[0] = 1;
				return data;
			}
			else
			{
				return data;
			}
		}

		public PrimaryUserID(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.PRIMARY_USER_ID, critical, isLongLength, data)
		{
		}

		public PrimaryUserID(bool critical, bool isPrimaryUserID) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.PRIMARY_USER_ID, critical, false, booleanToByteArray(isPrimaryUserID))
		{
		}

		public virtual bool isPrimaryUserID()
		{
			return data[0] != 0;
		}
	}

}