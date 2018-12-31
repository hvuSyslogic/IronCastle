using org.bouncycastle.crypto.@params;
using org.bouncycastle.crypto.signers;

namespace org.bouncycastle.crypto.tls
{
				
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