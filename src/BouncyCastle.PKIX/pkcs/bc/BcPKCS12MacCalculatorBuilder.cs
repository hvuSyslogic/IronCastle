namespace org.bouncycastle.pkcs.bc
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;

	public class BcPKCS12MacCalculatorBuilder : PKCS12MacCalculatorBuilder
	{
		private ExtendedDigest digest;
		private AlgorithmIdentifier algorithmIdentifier;

		private SecureRandom random;
		private int saltLength;
		private int iterationCount = 1024;

		public BcPKCS12MacCalculatorBuilder() : this(new SHA1Digest(), new AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE))
		{
		}

		public BcPKCS12MacCalculatorBuilder(ExtendedDigest digest, AlgorithmIdentifier algorithmIdentifier)
		{
			this.digest = digest;
			this.algorithmIdentifier = algorithmIdentifier;
			this.saltLength = digest.getDigestSize();
		}

		public virtual BcPKCS12MacCalculatorBuilder setIterationCount(int iterationCount)
		{
			this.iterationCount = iterationCount;

			return this;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithmIdentifier()
		{
			return algorithmIdentifier;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.MacCalculator build(final char[] password)
		public virtual MacCalculator build(char[] password)
		{
			if (random == null)
			{
				random = new SecureRandom();
			}

			byte[] salt = new byte[saltLength];

			random.nextBytes(salt);

			return PKCS12PBEUtils.createMacCalculator(algorithmIdentifier.getAlgorithm(), digest, new PKCS12PBEParams(salt, iterationCount), password);
		}
	}

}