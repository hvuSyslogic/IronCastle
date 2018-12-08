namespace org.bouncycastle.pkcs.bc
{
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using BcDigestProvider = org.bouncycastle.@operator.bc.BcDigestProvider;

	public class BcPKCS12MacCalculatorBuilderProvider : PKCS12MacCalculatorBuilderProvider
	{
		private BcDigestProvider digestProvider;

		public BcPKCS12MacCalculatorBuilderProvider(BcDigestProvider digestProvider)
		{
			this.digestProvider = digestProvider;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.pkcs.PKCS12MacCalculatorBuilder get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithmIdentifier)
		public virtual PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier)
		{
			return new PKCS12MacCalculatorBuilderAnonymousInnerClass(this, algorithmIdentifier);
		}

		public class PKCS12MacCalculatorBuilderAnonymousInnerClass : PKCS12MacCalculatorBuilder
		{
			private readonly BcPKCS12MacCalculatorBuilderProvider outerInstance;

			private AlgorithmIdentifier algorithmIdentifier;

			public PKCS12MacCalculatorBuilderAnonymousInnerClass(BcPKCS12MacCalculatorBuilderProvider outerInstance, AlgorithmIdentifier algorithmIdentifier)
			{
				this.outerInstance = outerInstance;
				this.algorithmIdentifier = algorithmIdentifier;
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.MacCalculator build(final char[] password) throws org.bouncycastle.operator.OperatorCreationException
			public MacCalculator build(char[] password)
			{
				PKCS12PBEParams pbeParams = PKCS12PBEParams.getInstance(algorithmIdentifier.getParameters());

				return PKCS12PBEUtils.createMacCalculator(algorithmIdentifier.getAlgorithm(), outerInstance.digestProvider.get(algorithmIdentifier), pbeParams, password);
			}

			public AlgorithmIdentifier getDigestAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(algorithmIdentifier.getAlgorithm(), DERNull.INSTANCE);
			}
		}
	}

}