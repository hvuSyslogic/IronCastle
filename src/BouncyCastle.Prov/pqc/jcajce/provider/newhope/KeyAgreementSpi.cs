namespace org.bouncycastle.pqc.jcajce.provider.newhope
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using BaseAgreementSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
	using ExchangePair = org.bouncycastle.pqc.crypto.ExchangePair;
	using NHAgreement = org.bouncycastle.pqc.crypto.newhope.NHAgreement;
	using NHExchangePairGenerator = org.bouncycastle.pqc.crypto.newhope.NHExchangePairGenerator;
	using NHPublicKeyParameters = org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;

	public class KeyAgreementSpi : BaseAgreementSpi
	{
		private NHAgreement agreement;
		private BCNHPublicKey otherPartyKey;
		private NHExchangePairGenerator exchangePairGenerator;

		private byte[] shared;

		public KeyAgreementSpi() : base("NH", null)
		{
		}

		public override void engineInit(Key key, SecureRandom secureRandom)
		{
			if (key != null)
			{
				agreement = new NHAgreement();

				agreement.init(((BCNHPrivateKey)key).getKeyParams());
			}
			else
			{
				exchangePairGenerator = new NHExchangePairGenerator(secureRandom);
			}
		}

		public override void engineInit(Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
		{
			throw new InvalidAlgorithmParameterException("NewHope does not require parameters");
		}

		public override Key engineDoPhase(Key key, bool lastPhase)
		{
			if (!lastPhase)
			{
				throw new IllegalStateException("NewHope can only be between two parties.");
			}

			otherPartyKey = (BCNHPublicKey)key;

			if (exchangePairGenerator != null)
			{
				ExchangePair exchPair = exchangePairGenerator.generateExchange((AsymmetricKeyParameter)otherPartyKey.getKeyParams());

				shared = exchPair.getSharedValue();

				return new BCNHPublicKey((NHPublicKeyParameters)exchPair.getPublicKey());
			}
			else
			{
				shared = agreement.calculateAgreement(otherPartyKey.getKeyParams());

				return null;
			}
		}

		public override byte[] engineGenerateSecret()
		{
			byte[] rv = Arrays.clone(shared);

			Arrays.fill(shared, (byte)0);

			return rv;
		}

		public override int engineGenerateSecret(byte[] bytes, int offset)
		{
			JavaSystem.arraycopy(shared, 0, bytes, offset, shared.Length);

			Arrays.fill(shared, (byte)0);

			return shared.Length;
		}

		public override byte[] calcSecret()
		{
			return engineGenerateSecret();
		}
	}

}