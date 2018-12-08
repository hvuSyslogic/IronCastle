namespace org.bouncycastle.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using SignatureAlgorithmIdentifierFinder = org.bouncycastle.@operator.SignatureAlgorithmIdentifierFinder;

	public class SignerInformationVerifier
	{
		private ContentVerifierProvider verifierProvider;
		private DigestCalculatorProvider digestProvider;
		private SignatureAlgorithmIdentifierFinder sigAlgorithmFinder;
		private CMSSignatureAlgorithmNameGenerator sigNameGenerator;

		public SignerInformationVerifier(CMSSignatureAlgorithmNameGenerator sigNameGenerator, SignatureAlgorithmIdentifierFinder sigAlgorithmFinder, ContentVerifierProvider verifierProvider, DigestCalculatorProvider digestProvider)
		{
			this.sigNameGenerator = sigNameGenerator;
			this.sigAlgorithmFinder = sigAlgorithmFinder;
			this.verifierProvider = verifierProvider;
			this.digestProvider = digestProvider;
		}

		public virtual bool hasAssociatedCertificate()
		{
			return verifierProvider.hasAssociatedCertificate();
		}

		public virtual X509CertificateHolder getAssociatedCertificate()
		{
			return verifierProvider.getAssociatedCertificate();
		}

		public virtual ContentVerifier getContentVerifier(AlgorithmIdentifier signingAlgorithm, AlgorithmIdentifier digestAlgorithm)
		{
			string signatureName = sigNameGenerator.getSignatureName(digestAlgorithm, signingAlgorithm);
			AlgorithmIdentifier baseAlgID = sigAlgorithmFinder.find(signatureName);

			return verifierProvider.get(new AlgorithmIdentifier(baseAlgID.getAlgorithm(), signingAlgorithm.getParameters()));
		}

		public virtual DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier)
		{
			return digestProvider.get(algorithmIdentifier);
		}
	}

}