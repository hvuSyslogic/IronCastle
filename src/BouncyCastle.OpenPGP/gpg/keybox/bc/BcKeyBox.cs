namespace org.bouncycastle.gpg.keybox.bc
{

	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	public class BcKeyBox : KeyBox
	{
		public BcKeyBox(byte[] encoding) : base(encoding, new BcKeyFingerprintCalculator(), new BcBlobVerifier())
		{
		}

		public BcKeyBox(InputStream input) : base(input, new BcKeyFingerprintCalculator(), new BcBlobVerifier())
		{
		}
	}

}