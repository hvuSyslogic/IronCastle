namespace org.bouncycastle.bcpg.sig
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// RFC 4880, Section 5.2.3.25 - Signature Target subpacket.
	/// </summary>
	public class SignatureTarget : SignatureSubpacket
	{
		public SignatureTarget(bool critical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.SIGNATURE_TARGET, critical, isLongLength, data)
		{
		}

		public SignatureTarget(bool critical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.SIGNATURE_TARGET, critical, false, Arrays.concatenate(new byte[] {(byte)publicKeyAlgorithm, (byte)hashAlgorithm}, hashData))
		{
		}

		public virtual int getPublicKeyAlgorithm()
		{
			return data[0] & 0xff;
		}

		public virtual int getHashAlgorithm()
		{
			return data[1] & 0xff;
		}

		public virtual byte[] getHashData()
		{
			return Arrays.copyOfRange(data, 2, data.Length);
		}
	}

}