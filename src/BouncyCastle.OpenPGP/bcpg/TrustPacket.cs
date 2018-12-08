namespace org.bouncycastle.bcpg
{

	/// <summary>
	/// Basic type for a trust packet
	/// </summary>
	public class TrustPacket : ContainedPacket
	{
		internal byte[] levelAndTrustAmount;

		public TrustPacket(BCPGInputStream @in)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			int ch;

			while ((ch = @in.read()) >= 0)
			{
				bOut.write(ch);
			}

			levelAndTrustAmount = bOut.toByteArray();
		}

		public TrustPacket(int trustCode)
		{
			this.levelAndTrustAmount = new byte[1];

			this.levelAndTrustAmount[0] = (byte)trustCode;
		}

		public virtual byte[] getLevelAndTrustAmount()
		{
			return levelAndTrustAmount;
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.writePacket(PacketTags_Fields.TRUST, levelAndTrustAmount, true);
		}
	}

}