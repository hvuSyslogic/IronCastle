namespace org.bouncycastle.cms.bc
{
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using SignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.SignatureAlgorithmIdentifierFinder;
	using BcRSAContentVerifierProviderBuilder = org.bouncycastle.@operator.bc.BcRSAContentVerifierProviderBuilder;

	public class BcRSASignerInfoVerifierBuilder
	{
		private BcRSAContentVerifierProviderBuilder contentVerifierProviderBuilder;
		private DigestCalculatorProvider digestCalculatorProvider;
		private CMSSignatureAlgorithmNameGenerator sigAlgNameGen;
		private SignatureAlgorithmIdentifierFinder sigAlgIdFinder;

		public BcRSASignerInfoVerifierBuilder(CMSSignatureAlgorithmNameGenerator sigAlgNameGen, SignatureAlgorithmIdentifierFinder sigAlgIdFinder, DigestAlgorithmIdentifierFinder digestAlgorithmFinder, DigestCalculatorProvider digestCalculatorProvider)
		{
			this.sigAlgNameGen = sigAlgNameGen;
			this.sigAlgIdFinder = sigAlgIdFinder;
			this.contentVerifierProviderBuilder = new BcRSAContentVerifierProviderBuilder(digestAlgorithmFinder);
			this.digestCalculatorProvider = digestCalculatorProvider;
		}

		public virtual SignerInformationVerifier build(X509CertificateHolder certHolder)
		{
			return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(certHolder), digestCalculatorProvider);
		}

		public virtual SignerInformationVerifier build(AsymmetricKeyParameter pubKey)
		{
			return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(pubKey), digestCalculatorProvider);
		}
	}

}