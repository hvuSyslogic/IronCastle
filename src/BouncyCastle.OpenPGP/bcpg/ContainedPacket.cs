namespace org.bouncycastle.bcpg
{

	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Basic type for a PGP packet.
	/// </summary>
	public abstract class ContainedPacket : Packet, Encodable
	{
		public virtual byte[] getEncoded()
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			BCPGOutputStream pOut = new BCPGOutputStream(bOut);

			pOut.writePacket(this);

			pOut.close();

			return bOut.toByteArray();
		}

		public abstract void encode(BCPGOutputStream pOut);
	}

}