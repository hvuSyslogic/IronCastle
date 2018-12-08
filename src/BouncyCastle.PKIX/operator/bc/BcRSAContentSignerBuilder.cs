namespace org.bouncycastle.@operator.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using Signer = org.bouncycastle.crypto.Signer;
	using RSADigestSigner = org.bouncycastle.crypto.signers.RSADigestSigner;

	public class BcRSAContentSignerBuilder : BcContentSignerBuilder
	{
		public BcRSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) : base(sigAlgId, digAlgId)
		{
		}

		public override Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
		{
			Digest dig = digestProvider.get(digAlgId);

			return new RSADigestSigner(dig);
		}
	}

}