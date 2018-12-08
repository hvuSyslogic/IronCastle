namespace org.bouncycastle.openpgp.bc
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;
	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	public class BcPGPPublicKeyRing : PGPPublicKeyRing
	{
		private static KeyFingerPrintCalculator fingerPrintCalculator = new BcKeyFingerprintCalculator();

		public BcPGPPublicKeyRing(byte[] encoding) : base(encoding, fingerPrintCalculator)
		{
		}

		public BcPGPPublicKeyRing(InputStream @in) : base(@in, fingerPrintCalculator)
		{
		}
	}

}