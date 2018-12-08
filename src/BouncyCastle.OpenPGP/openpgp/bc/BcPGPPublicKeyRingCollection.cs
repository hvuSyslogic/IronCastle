namespace org.bouncycastle.openpgp.bc
{

	using BcKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.bc.BcKeyFingerprintCalculator;

	public class BcPGPPublicKeyRingCollection : PGPPublicKeyRingCollection
	{
		public BcPGPPublicKeyRingCollection(byte[] encoding) : this(new ByteArrayInputStream(encoding))
		{
		}

		public BcPGPPublicKeyRingCollection(InputStream @in) : base(@in, new BcKeyFingerprintCalculator())
		{
		}

		public BcPGPPublicKeyRingCollection(Collection collection) : base(collection)
		{
		}
	}

}