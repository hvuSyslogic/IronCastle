namespace org.bouncycastle.openpgp.@operator
{
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;

	public interface KeyFingerPrintCalculator
	{
		byte[] calculateFingerprint(PublicKeyPacket publicPk);
	}

}