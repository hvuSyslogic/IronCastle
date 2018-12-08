namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// packet giving trust.
	/// </summary>
	public class TrustSignature : SignatureSubpacket
	{
		private static byte[] intToByteArray(int v1, int v2)
		{
			byte[] data = new byte[2];

			data[0] = (byte)v1;
			data[1] = (byte)v2;

			return data;
		}

		public TrustSignature(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.TRUST_SIG, critical, isLongLength, data)
		{
		}

		public TrustSignature(bool critical, int depth, int trustAmount) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.TRUST_SIG, critical, false, intToByteArray(depth, trustAmount))
		{
		}

		public virtual int getDepth()
		{
			return data[0] & 0xff;
		}

		public virtual int getTrustAmount()
		{
			return data[1] & 0xff;
		}
	}

}