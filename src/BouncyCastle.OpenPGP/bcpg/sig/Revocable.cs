namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving whether or not is revocable.
	/// </summary>
	public class Revocable : SignatureSubpacket
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

		public Revocable(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCABLE, critical, isLongLength, data)
		{
		}

		public Revocable(bool critical, bool isRevocable) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCABLE, critical, false, booleanToByteArray(isRevocable))
		{
		}

		public virtual bool isRevocable()
		{
			return data[0] != 0;
		}
	}

}