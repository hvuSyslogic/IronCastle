namespace org.bouncycastle.crypto.tls
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using ECDSASigner = org.bouncycastle.crypto.signers.ECDSASigner;
	using HMacDSAKCalculator = org.bouncycastle.crypto.signers.HMacDSAKCalculator;

	public class TlsECDSASigner : TlsDSASigner
	{
		public override bool isValidPublicKey(AsymmetricKeyParameter publicKey)
		{
			return publicKey is ECPublicKeyParameters;
		}

		public override DSA createDSAImpl(short hashAlgorithm)
		{
			return new ECDSASigner(new HMacDSAKCalculator(TlsUtils.createHash(hashAlgorithm)));
		}

		public override short getSignatureAlgorithm()
		{
			return SignatureAlgorithm.ecdsa;
		}
	}

}