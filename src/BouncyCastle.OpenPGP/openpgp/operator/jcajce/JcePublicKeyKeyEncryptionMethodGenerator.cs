using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using X9ECPoint = org.bouncycastle.asn1.x9.X9ECPoint;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class JcePublicKeyKeyEncryptionMethodGenerator : PublicKeyKeyEncryptionMethodGenerator
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
		private SecureRandom random;
		private JcaPGPKeyConverter keyConverter = new JcaPGPKeyConverter();

		/// <summary>
		/// Create a public key encryption method generator with the method to be based on the passed in key.
		/// </summary>
		/// <param name="key">   the public key to use for encryption. </param>
		public JcePublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key) : base(key)
		{
		}

		public virtual JcePublicKeyKeyEncryptionMethodGenerator setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			keyConverter.setProvider(provider);

			return this;
		}

		public virtual JcePublicKeyKeyEncryptionMethodGenerator setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			keyConverter.setProvider(providerName);

			return this;
		}

		/// <summary>
		/// Provide a user defined source of randomness.
		/// </summary>
		/// <param name="random">  the secure random to be used. </param>
		/// <returns>  the current generator. </returns>
		public virtual JcePublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public override byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
		{
			try
			{
				if (pubKey.getAlgorithm() == PublicKeyAlgorithmTags_Fields.ECDH)
				{
					// Generate the ephemeral key pair
					ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKey.getPublicKeyPacket().getKey();
					X9ECParameters x9Params = JcaJcePGPUtil.getX9Parameters(ecKey.getCurveOID());
					AlgorithmParameters ecAlgParams = helper.createAlgorithmParameters("EC");

					ecAlgParams.init((new X962Parameters(ecKey.getCurveOID())).getEncoded());

					KeyPairGenerator kpGen = helper.createKeyPairGenerator("EC");

					kpGen.initialize(ecAlgParams.getParameterSpec(typeof(AlgorithmParameterSpec)));

					KeyPair ephKP = kpGen.generateKeyPair();

					KeyAgreement agreement = helper.createKeyAgreement(RFC6637Utils.getAgreementAlgorithm(pubKey.getPublicKeyPacket()));

					agreement.init(ephKP.getPrivate(), new UserKeyingMaterialSpec(RFC6637Utils.createUserKeyingMaterial(pubKey.getPublicKeyPacket(), new JcaKeyFingerprintCalculator())));

					agreement.doPhase(keyConverter.getPublicKey(pubKey), true);

					Key key = agreement.generateSecret(RFC6637Utils.getKeyEncryptionOID(ecKey.getSymmetricKeyAlgorithm()).getId());

					Cipher c = helper.createKeyWrapper(ecKey.getSymmetricKeyAlgorithm());

					c.init(Cipher.WRAP_MODE, key, random);

					byte[] paddedSessionData = PGPPad.padSessionData(sessionInfo);

					byte[] C = c.wrap(new SecretKeySpec(paddedSessionData, PGPUtil.getSymmetricCipherName(sessionInfo[0])));

					SubjectPublicKeyInfo epPubKey = SubjectPublicKeyInfo.getInstance(ephKP.getPublic().getEncoded());

					X9ECPoint derQ = new X9ECPoint(x9Params.getCurve(), epPubKey.getPublicKeyData().getBytes());

					ECPoint publicPoint = derQ.getPoint();

					byte[] VB = (new MPInteger(new BigInteger(1, publicPoint.getEncoded(false)))).getEncoded();

					byte[] rv = new byte[VB.Length + 1 + C.Length];

					JavaSystem.arraycopy(VB, 0, rv, 0, VB.Length);
					rv[VB.Length] = (byte)C.Length;
					JavaSystem.arraycopy(C, 0, rv, VB.Length + 1, C.Length);

					return rv;
				}
				else
				{
					Cipher c = helper.createPublicKeyCipher(pubKey.getAlgorithm());

					Key key = keyConverter.getPublicKey(pubKey);

					c.init(Cipher.ENCRYPT_MODE, key, random);

					return c.doFinal(sessionInfo);
				}
			}
			catch (IllegalBlockSizeException e)
			{
				throw new PGPException("illegal block size: " + e.Message, e);
			}
			catch (BadPaddingException e)
			{
				throw new PGPException("bad padding: " + e.Message, e);
			}
			catch (InvalidKeyException e)
			{
				throw new PGPException("key invalid: " + e.Message, e);
			}
			catch (IOException e)
			{
				throw new PGPException("unable to encode MPI: " + e.Message, e);
			}
			catch (GeneralSecurityException e)
			{
				throw new PGPException("unable to set up ephemeral keys: " + e.Message, e);
			}
		}
	}

}