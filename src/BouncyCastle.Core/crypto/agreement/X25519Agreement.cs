﻿using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.agreement
{
		
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