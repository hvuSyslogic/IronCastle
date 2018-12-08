namespace org.bouncycastle.pqc.crypto.newhope
{
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;

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