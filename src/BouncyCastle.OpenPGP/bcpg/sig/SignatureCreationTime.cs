using System;

namespace org.bouncycastle.bcpg.sig
{


	/// <summary>
	/// packet giving signature creation time.
	/// </summary>
	public class SignatureCreationTime : SignatureSubpacket
	{
		protected internal static byte[] timeToBytes(DateTime date)
		{
			byte[] data = new byte[4];
			long t = date.Ticks / 1000;

			data[0] = (byte)(t >> 24);
			data[1] = (byte)(t >> 16);
			data[2] = (byte)(t >> 8);
			data[3] = (byte)t;

			return data;
		}

		public SignatureCreationTime(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.CREATION_TIME, critical, isLongLength, data)
		{
		}

		public SignatureCreationTime(bool critical, DateTime date) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.CREATION_TIME, critical, false, timeToBytes(date))
		{
		}

		public virtual DateTime getTime()
		{
			long time = ((long)(data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff);

			return new DateTime(time * 1000);
		}
	}

}