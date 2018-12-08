namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// Packet embedded signature
	/// </summary>
	public class EmbeddedSignature : SignatureSubpacket
	{
		public EmbeddedSignature(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.EMBEDDED_SIGNATURE, critical, isLongLength, data)
		{
		}
	}
}