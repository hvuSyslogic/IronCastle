using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.signers;

namespace org.bouncycastle.crypto.tls
{
				
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