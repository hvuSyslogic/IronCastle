namespace org.bouncycastle.openpgp.bc
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	public class BcPGPSecretKeyRing : PGPSecretKeyRing
	{
		private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

		public BcPGPSecretKeyRing(byte[] encoding) : base(encoding, fingerPrintCalculator)
		{
		}

		public BcPGPSecretKeyRing(InputStream @in) : base(@in, fingerPrintCalculator)
		{
		}
	}

}