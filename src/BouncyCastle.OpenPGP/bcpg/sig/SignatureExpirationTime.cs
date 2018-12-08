namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving signature expiration time.
	/// </summary>
	public class SignatureExpirationTime : SignatureSubpacket
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

		public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.EXPIRE_TIME, critical, isLongLength, data)
		{
		}

		public SignatureExpirationTime(bool critical, long seconds) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.EXPIRE_TIME, critical, false, timeToBytes(seconds))
		{
		}

		/// <summary>
		/// return time in seconds before signature expires after creation time.
		/// </summary>
		public virtual long getTime()
		{
			long time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);

			return time;
		}
	}

}