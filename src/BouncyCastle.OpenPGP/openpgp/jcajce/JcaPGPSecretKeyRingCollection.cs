namespace org.bouncycastle.openpgp.jcajce
{

	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;

	public class JcaPGPSecretKeyRingCollection : PGPSecretKeyRingCollection
	{
		public JcaPGPSecretKeyRingCollection(byte[] encoding) : this(new ByteArrayInputStream(encoding))
		{
		}

		public JcaPGPSecretKeyRingCollection(InputStream @in) : base(@in, new JcaKeyFingerprintCalculator())
		{
		}

		public JcaPGPSecretKeyRingCollection(Collection collection) : base(collection)
		{
		}
	}

}