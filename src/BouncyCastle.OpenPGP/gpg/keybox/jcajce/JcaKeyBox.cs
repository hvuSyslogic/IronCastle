namespace org.bouncycastle.gpg.keybox.jcajce
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;

	public class JcaKeyBox : KeyBox
	{
		public JcaKeyBox(byte[] encoding, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier) : base(encoding, fingerPrintCalculator, verifier)
		{
		}

		public JcaKeyBox(InputStream input, KeyFingerPrintCalculator fingerPrintCalculator, BlobVerifier verifier) : base(input, fingerPrintCalculator, verifier)
		{
		}
	}

}