using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.agreement
{
		
	public sealed class X448Agreement : RawAgreement
	{
		private X448PrivateKeyParameters privateKey;

		public void init(CipherParameters parameters)
		{
			this.privateKey = (X448PrivateKeyParameters)parameters;
		}

		public int getAgreementSize()
		{
			return X448PrivateKeyParameters.SECRET_SIZE;
		}

		public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
		{
			privateKey.generateSecret((X448PublicKeyParameters)publicKey, buf, off);
		}
	}

}