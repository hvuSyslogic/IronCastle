namespace org.bouncycastle.@operator.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using Signer = org.bouncycastle.crypto.Signer;
	using DSADigestSigner = org.bouncycastle.crypto.signers.DSADigestSigner;
	using ECDSASigner = org.bouncycastle.crypto.signers.ECDSASigner;

	public class BcECContentSignerBuilder : BcContentSignerBuilder
	{
		public BcECContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId) : base(sigAlgId, digAlgId)
		{
		}

		public override Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
		{
			Digest dig = digestProvider.get(digAlgId);

			return new DSADigestSigner(new ECDSASigner(), dig);
		}
	}

}