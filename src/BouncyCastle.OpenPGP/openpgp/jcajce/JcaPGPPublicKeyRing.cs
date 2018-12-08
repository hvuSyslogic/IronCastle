namespace org.bouncycastle.openpgp.jcajce
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	public class JcaPGPPublicKeyRing : PGPPublicKeyRing
	{
		private static KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

		public JcaPGPPublicKeyRing(byte[] encoding) : base(encoding, fingerPrintCalculator)
		{
		}

		public JcaPGPPublicKeyRing(InputStream @in) : base(@in, fingerPrintCalculator)
		{
		}
	}

}