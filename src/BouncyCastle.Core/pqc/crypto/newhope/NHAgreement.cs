using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.newhope
{
	
	public class NHAgreement
	{
		private NHPrivateKeyParameters privKey;

		public virtual void init(CipherParameters param)
		{
			privKey = (NHPrivateKeyParameters)param;
		}

		public virtual byte[] calculateAgreement(CipherParameters otherPublicKey)
		{
			NHPublicKeyParameters pubKey = (NHPublicKeyParameters)otherPublicKey;

			byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];

			NewHope.sharedA(sharedValue, privKey.secData, pubKey.pubData);

			return sharedValue;
		}
	}

}