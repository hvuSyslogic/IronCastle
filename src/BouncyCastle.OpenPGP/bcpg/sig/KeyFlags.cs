namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// Packet holding the key flag values.
	/// </summary>
	public class KeyFlags : SignatureSubpacket
	{
		public const int CERTIFY_OTHER = 0x01;
		public const int SIGN_DATA = 0x02;
		public const int ENCRYPT_COMMS = 0x04;
		public const int ENCRYPT_STORAGE = 0x08;
		public const int SPLIT = 0x10;
		public const int AUTHENTICATION = 0x20;
		public const int SHARED = 0x80;

		private static byte[] intToByteArray(int v)
		{
			byte[] tmp = new byte[4];
			int size = 0;

			for (int i = 0; i != 4; i++)
			{
				tmp[i] = (byte)(v >> (i * 8));
				if (tmp[i] != 0)
				{
					size = i;
				}
			}

			byte[] data = new byte[size + 1];

			JavaSystem.arraycopy(tmp, 0, data, 0, data.Length);

			return data;
		}

		public KeyFlags(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.KEY_FLAGS, critical, isLongLength, data)
		{
		}

		public KeyFlags(bool critical, int flags) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.KEY_FLAGS, critical, false, intToByteArray(flags))
		{
		}

		/// <summary>
		/// Return the flag values contained in the first 4 octets (note: at the moment
		/// the standard only uses the first one).
		/// </summary>
		/// <returns> flag values. </returns>
		public virtual int getFlags()
		{
			int flags = 0;

			for (int i = 0; i != data.Length; i++)
			{
				flags |= (data[i] & 0xff) << (i * 8);
			}

			return flags;
		}
	}

}