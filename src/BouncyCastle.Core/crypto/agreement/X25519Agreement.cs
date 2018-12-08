namespace org.bouncycastle.crypto.agreement
{
	using X25519PrivateKeyParameters = org.bouncycastle.crypto.@params.X25519PrivateKeyParameters;
	using X25519PublicKeyParameters = org.bouncycastle.crypto.@params.X25519PublicKeyParameters;

	public sealed class X25519Agreement : RawAgreement
	{
		private X25519PrivateKeyParameters privateKey;

		public void init(CipherParameters parameters)
		{
			this.privateKey = (X25519PrivateKeyParameters)parameters;
		}

		public int getAgreementSize()
		{
			return X25519PrivateKeyParameters.SECRET_SIZE;
		}

		public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
		{
			privateKey.generateSecret((X25519PublicKeyParameters)publicKey, buf, off);
		}
	}

}