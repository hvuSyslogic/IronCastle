namespace org.bouncycastle.crypto.tls
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using DSASigner = org.bouncycastle.crypto.signers.DSASigner;
	using HMacDSAKCalculator = org.bouncycastle.crypto.signers.HMacDSAKCalculator;

	public class TlsDSSSigner : TlsDSASigner
	{
		public override bool isValidPublicKey(AsymmetricKeyParameter publicKey)
		{
			return publicKey is DSAPublicKeyParameters;
		}

		public override DSA createDSAImpl(short hashAlgorithm)
		{
			return new DSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
		}

		public override short getSignatureAlgorithm()
		{
			return SignatureAlgorithm.dsa;
		}
	}

}