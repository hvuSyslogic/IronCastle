namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Digest = org.bouncycastle.crypto.Digest;
	using Signer = org.bouncycastle.crypto.Signer;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSADigestSigner = org.bouncycastle.crypto.signers.DSADigestSigner;
	using ECDSASigner = org.bouncycastle.crypto.signers.ECDSASigner;
	using PublicKeyFactory = org.bouncycastle.crypto.util.PublicKeyFactory;

	public class BcECContentVerifierProviderBuilder : BcContentVerifierProviderBuilder
	{
		private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

		public BcECContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
		{
			this.digestAlgorithmFinder = digestAlgorithmFinder;
		}

		public override Signer createSigner(AlgorithmIdentifier sigAlgId)
		{
			AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
			Digest dig = digestProvider.get(digAlg);

			return new DSADigestSigner(new ECDSASigner(), dig);
		}

		public override AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
		{
			return PublicKeyFactory.createKey(publicKeyInfo);
		}
	}

}