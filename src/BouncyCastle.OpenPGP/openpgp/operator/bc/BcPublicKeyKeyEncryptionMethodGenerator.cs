namespace org.bouncycastle.openpgp.@operator.bc
{

	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using EphemeralKeyPair = org.bouncycastle.crypto.EphemeralKeyPair;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using KeyEncoder = org.bouncycastle.crypto.KeyEncoder;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using EphemeralKeyPairGenerator = org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// A method generator for supporting public key based encryption operations.
	/// </summary>
	public class BcPublicKeyKeyEncryptionMethodGenerator : PublicKeyKeyEncryptionMethodGenerator
	{
		private SecureRandom random;
		private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

		/// <summary>
		/// Create a public key encryption method generator with the method to be based on the passed in key.
		/// </summary>
		/// <param name="key">   the public key to use for encryption. </param>
		public BcPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) : base(key)
		{
		}

		/// <summary>
		/// Provide a user defined source of randomness.
		/// </summary>
		/// <param name="random">  the secure random to be used. </param>
		/// <returns>  the current generator. </returns>
		public virtual BcPublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
		{
			try
			{
				if (pubKey.getAlgorithm() != PGPPublicKey.ECDH)
				{
					AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(pubKey.getAlgorithm());

					AsymmetricKeyParameter key = keyConverter.getPublicKey(pubKey);

					if (random == null)
					{
						random = new SecureRandom();
					}

					c.init(true, new ParametersWithRandom(key, random));

					return c.processBlock(sessionInfo, 0, sessionInfo.Length);
				}
				else
				{
					ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					X9ECParameters x9Params = BcUtil.getX9Parameters(ecKey.getCurveOID());
					ECDomainParameters ecParams = new ECDomainParameters(x9Params.getCurve(), x9Params.getG(), x9Params.getN());

					// Generate the ephemeral key pair
					ECKeyPairGenerator gen = new ECKeyPairGenerator();
					gen.init(new ECKeyGenerationParameters(ecParams, random));

					EphemeralKeyPairGenerator kGen = new EphemeralKeyPairGenerator(gen, new KeyEncoderAnonymousInnerClass(this));

					EphemeralKeyPair ephKp = kGen.generate();

					ECPrivateKeyParameters ephPriv = (ECPrivateKeyParameters)ephKp.getKeyPair().getPrivate();

					ECPoint S = BcUtil.decodePoint(ecKey.getEncodedPoint(), x9Params.getCurve()).multiply(ephPriv.getD()).normalize();

					RFC6637KDFCalculator rfc6637KDFCalculator = new RFC6637KDFCalculator((new BcPGPDigestCalculatorProvider()).get(ecKey.getHashAlgorithm()), ecKey.getSymmetricKeyAlgorithm());

					KeyParameter key = new KeyParameter(rfc6637KDFCalculator.createKey(S, RFC6637Utils.createUserKeyingMaterial(pubKey.getPublicKeyPacket(), new BcKeyFingerprintCalculator())));

					Wrapper c = BcImplProvider.createWrapper(ecKey.getSymmetricKeyAlgorithm());

					c.init(true, new ParametersWithRandom(key, random));

					byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo);

					byte[] C = c.wrap(paddedSessionData, 0, paddedSessionData.Length);
					byte[] VB = (new MPInteger(new BigInteger(1, ephKp.getEncodedPublicKey()))).getEncoded();

					byte[] rv = new byte[VB.Length + 1 + C.Length];

					JavaSystem.arraycopy(VB, 0, rv, 0, VB.Length);
					rv[VB.Length] = (byte)C.Length;
					JavaSystem.arraycopy(C, 0, rv, VB.Length + 1, C.Length);

					return rv;
				}
			}
			catch (InvalidCipherTextException e)
			{
				throw new PGPException("exception encrypting session info: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new PGPException("exception encrypting session info: " + e.Message, e);
			}
		}

		public class KeyEncoderAnonymousInnerClass : KeyEncoder
		{
			private readonly BcPublicKeyKeyEncryptionMethodGenerator outerInstance;

			public KeyEncoderAnonymousInnerClass(BcPublicKeyKeyEncryptionMethodGenerator outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public byte[] getEncoded(AsymmetricKeyParameter keyParameter)
			{
				return ((ECPublicKeyParameters)keyParameter).getQ().getEncoded(false);
			}
		}
	}

}