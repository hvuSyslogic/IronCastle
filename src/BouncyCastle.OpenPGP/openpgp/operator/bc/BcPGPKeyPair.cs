using System;

namespace org.bouncycastle.openpgp.@operator.bc
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public class BcPGPKeyPair : PGPKeyPair
	{
		private static PGPPublicKey getPublicKey(int algorithm, PGPAlgorithmParameters parameters, AsymmetricKeyParameter pubKey, DateTime date)
		{
			return (new BcPGPKeyConverter()).getPGPPublicKey(algorithm, parameters, pubKey, date);
		}

		private static PGPPrivateKey getPrivateKey(PGPPublicKey pub, AsymmetricKeyParameter privKey)
		{
			return (new BcPGPKeyConverter()).getPGPPrivateKey(pub, privKey);
		}

		public BcPGPKeyPair(int algorithm, AsymmetricCipherKeyPair keyPair, DateTime date)
		{
			this.pub = getPublicKey(algorithm, null, keyPair.getPublic(), date);
			this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
		}

		public BcPGPKeyPair(int algorithm, PGPAlgorithmParameters parameters, AsymmetricCipherKeyPair keyPair, DateTime date)
		{
			this.pub = getPublicKey(algorithm, parameters, keyPair.getPublic(), date);
			this.priv = getPrivateKey(this.pub, keyPair.getPrivate());
		}
	}

}