namespace org.bouncycastle.openpgp.jcajce
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	public class JcaPGPSecretKeyRing : PGPSecretKeyRing
	{
		private static KeyFingerPrintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();

		public JcaPGPSecretKeyRing(byte[] encoding) : base(encoding, fingerPrintCalculator)
		{
		}

		public JcaPGPSecretKeyRing(InputStream @in) : base(@in, fingerPrintCalculator)
		{
		}
	}

}