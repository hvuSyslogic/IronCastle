namespace org.bouncycastle.openpgp.jcajce
{

	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	public class JcaPGPPublicKeyRingCollection : PGPPublicKeyRingCollection
	{
		public JcaPGPPublicKeyRingCollection(byte[] encoding) : this(new ByteArrayInputStream(encoding))
		{
		}

		public JcaPGPPublicKeyRingCollection(InputStream @in) : base(@in, new JcaKeyFingerprintCalculator())
		{
		}

		public JcaPGPPublicKeyRingCollection(Collection collection) : base(collection)
		{
		}
	}

}