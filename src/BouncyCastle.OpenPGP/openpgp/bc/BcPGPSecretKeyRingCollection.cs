namespace org.bouncycastle.openpgp.bc
{

	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	public class BcPGPSecretKeyRingCollection : PGPSecretKeyRingCollection
	{
		public BcPGPSecretKeyRingCollection(byte[] encoding) : this(new ByteArrayInputStream(encoding))
		{
		}

		public BcPGPSecretKeyRingCollection(InputStream @in) : base(@in, new BcKeyFingerprintCalculator())
		{
		}

		public BcPGPSecretKeyRingCollection(Collection collection) : base(collection)
		{
		}
	}

}