using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	/// <summary>
	/// Key pair generator for XMSS keys.
	/// </summary>
	public sealed class XMSSKeyPairGenerator
	{
		private XMSSParameters @params;
		private SecureRandom prng;

		/// <summary>
		/// Base constructor...
		/// </summary>
		public XMSSKeyPairGenerator()
		{
		}

		public void init(KeyGenerationParameters param)
		{
			XMSSKeyGenerationParameters parameters = (XMSSKeyGenerationParameters)param;

			this.prng = parameters.getRandom();
			this.@params = parameters.getParameters();
		}

		/// <summary>
		/// Generate a new XMSS private key / public key pair.
		/// </summary>
		public AsymmetricCipherKeyPair generateKeyPair()
		{
			/* generate private key */
			XMSSPrivateKeyParameters privateKey = generatePrivateKey(@params, prng);
			XMSSNode root = privateKey.getBDSState().getRoot();

			privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(privateKey.getSecretKeySeed()).withSecretKeyPRF(privateKey.getSecretKeyPRF()).withPublicSeed(privateKey.getPublicSeed()).withRoot(root.getValue()).withBDSState(privateKey.getBDSState()).build();

			XMSSPublicKeyParameters publicKey = (new XMSSPublicKeyParameters.Builder(@params)).withRoot(root.getValue()).withPublicSeed(privateKey.getPublicSeed()).build();

			return new AsymmetricCipherKeyPair(publicKey, privateKey);
		}

		/// <summary>
		/// Generate an XMSS private key.
		/// </summary>
		/// <returns> XMSS private key. </returns>
		private XMSSPrivateKeyParameters generatePrivateKey(XMSSParameters @params, SecureRandom prng)
		{
			int n = @params.getDigestSize();
			byte[] secretKeySeed = new byte[n];
			prng.nextBytes(secretKeySeed);
			byte[] secretKeyPRF = new byte[n];
			prng.nextBytes(secretKeyPRF);
			byte[] publicSeed = new byte[n];
			prng.nextBytes(publicSeed);

			XMSSPrivateKeyParameters privateKey = (new XMSSPrivateKeyParameters.Builder(@params)).withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF).withPublicSeed(publicSeed).withBDSState(new BDS(@params, publicSeed, secretKeySeed, (OTSHashAddress)(new OTSHashAddress.Builder()).build())).build();

			return privateKey;
		}
	}

}