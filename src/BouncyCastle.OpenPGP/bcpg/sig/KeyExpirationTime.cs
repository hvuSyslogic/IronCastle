namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving time after creation at which the key expires.
	/// </summary>
	public class KeyExpirationTime : SignatureSubpacket
	{
		protected internal static byte[] timeToBytes(long t)
		{
			byte[] data = new byte[4];

			data[0] = (byte)(t >> 24);
			data[1] = (byte)(t >> 16);
			data[2] = (byte)(t >> 8);
			data[3] = (byte)t;

			return data;
		}

		public KeyExpirationTime(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.KEY_EXPIRE_TIME, critical, isLongLength, data)
		{
		}

		public KeyExpirationTime(bool critical, long seconds) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.KEY_EXPIRE_TIME, critical, false, timeToBytes(seconds))
		{
		}

		/// <summary>
		/// Return the number of seconds after creation time a key is valid for.
		/// </summary>
		/// <returns> second count for key validity. </returns>
		public virtual long getTime()
		{
			long time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);

			return time;
		}
	}

}