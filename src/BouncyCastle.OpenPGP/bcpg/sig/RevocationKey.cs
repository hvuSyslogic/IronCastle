namespace org.bouncycastle.bcpg.sig
{

	/// <summary>
	/// Represents revocation key OpenPGP signature sub packet.
	/// </summary>
	public class RevocationKey : SignatureSubpacket
	{
		// 1 octet of class, 
		// 1 octet of public-key algorithm ID, 
		// 20 octets of fingerprint
		public RevocationKey(bool isCritical, bool isLongLength, byte[] data) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCATION_KEY, isCritical, isLongLength, data)
		{
		}

		public RevocationKey(bool isCritical, byte signatureClass, int keyAlgorithm, byte[] fingerprint) : base(org.bouncycastle.bcpg.SignatureSubpacketTags_Fields.REVOCATION_KEY, isCritical, false, createData(signatureClass, unchecked((byte)(keyAlgorithm & 0xff)), fingerprint))
		{
		}

		private static byte[] createData(byte signatureClass, byte keyAlgorithm, byte[] fingerprint)
		{
			byte[] data = new byte[2 + fingerprint.Length];
			data[0] = signatureClass;
			data[1] = keyAlgorithm;
			JavaSystem.arraycopy(fingerprint, 0, data, 2, fingerprint.Length);
			return data;
		}

		public virtual byte getSignatureClass()
		{
			return this.getData()[0];
		}

		public virtual int getAlgorithm()
		{
			return this.getData()[1];
		}

		public virtual byte[] getFingerprint()
		{
			byte[] data = this.getData();
			byte[] fingerprint = new byte[data.Length - 2];
			JavaSystem.arraycopy(data, 2, fingerprint, 0, fingerprint.Length);
			return fingerprint;
		}
	}

}