namespace org.bouncycastle.pqc.crypto.test
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using Signer = org.bouncycastle.crypto.Signer;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using GMSSDigestProvider = org.bouncycastle.pqc.crypto.gmss.GMSSDigestProvider;
	using GMSSKeyGenerationParameters = org.bouncycastle.pqc.crypto.gmss.GMSSKeyGenerationParameters;
	using GMSSKeyPairGenerator = org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator;
	using GMSSParameters = org.bouncycastle.pqc.crypto.gmss.GMSSParameters;
	using GMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.gmss.GMSSPrivateKeyParameters;
	using GMSSSigner = org.bouncycastle.pqc.crypto.gmss.GMSSSigner;
	using GMSSStateAwareSigner = org.bouncycastle.pqc.crypto.gmss.GMSSStateAwareSigner;
	using BigIntegers = org.bouncycastle.util.BigIntegers;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using FixedSecureRandom = org.bouncycastle.util.test.FixedSecureRandom;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;


	public class GMSSSignerTest : SimpleTest
	{
		private bool InstanceFieldsInitialized = false;

		public GMSSSignerTest()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
		}

		private void InitializeInstanceFields()
		{
			keyRandom = new FixedSecureRandom(new FixedSecureRandom.Source[]
			{
				new FixedSecureRandom.Data(keyData),
				new FixedSecureRandom.Data(keyData)
			});
		}

		internal byte[] keyData = Hex.decode("b5014e4b60ef2ba8b6211b4062ba3224e0427dd3");

		internal SecureRandom keyRandom;

		public override string getName()
		{
			return "GMSS";
		}

		public override void performTest()
		{

			GMSSParameters @params = new GMSSParameters(3, new int[]{15, 15, 10}, new int[]{5, 5, 4}, new int[]{3, 3, 2});

			GMSSDigestProvider digProvider = new GMSSDigestProviderAnonymousInnerClass(this);

			GMSSKeyPairGenerator gmssKeyGen = new GMSSKeyPairGenerator(digProvider);

			GMSSKeyGenerationParameters genParam = new GMSSKeyGenerationParameters(keyRandom, @params);

			gmssKeyGen.init(genParam);

			AsymmetricCipherKeyPair pair = gmssKeyGen.generateKeyPair();

			GMSSPrivateKeyParameters privKey = (GMSSPrivateKeyParameters)pair.getPrivate();

			ParametersWithRandom param = new ParametersWithRandom(privKey, keyRandom);

			// TODO
			Signer gmssSigner = new DigestingMessageSigner(new GMSSSigner(digProvider), new SHA224Digest());
			gmssSigner.init(true, param);

			byte[] message = BigIntegers.asUnsignedByteArray(new BigInteger("968236873715988614170569073515315707566766479517"));
			gmssSigner.update(message, 0, message.Length);
			byte[] sig = gmssSigner.generateSignature();


			gmssSigner.init(false, pair.getPublic());
			gmssSigner.update(message, 0, message.Length);
			if (!gmssSigner.verifySignature(sig))
			{
				fail("verification fails");
			}

			if (!((GMSSPrivateKeyParameters)pair.getPrivate()).isUsed())
			{
				fail("private key not marked as used");
			}

			stateAwareTest(privKey.nextKey(), pair.getPublic());
		}

		public class GMSSDigestProviderAnonymousInnerClass : GMSSDigestProvider
		{
			private readonly GMSSSignerTest outerInstance;

			public GMSSDigestProviderAnonymousInnerClass(GMSSSignerTest outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public Digest get()
			{
				return new SHA224Digest();
			}
		}

		private void stateAwareTest(GMSSPrivateKeyParameters privKey, AsymmetricKeyParameter pub)
		{
			DigestingStateAwareMessageSigner statefulSigner = new DigestingStateAwareMessageSigner(new GMSSStateAwareSigner(new SHA224Digest()), new SHA224Digest());
			statefulSigner.init(true, new ParametersWithRandom(privKey, CryptoServicesRegistrar.getSecureRandom()));

			byte[] mes1 = Strings.toByteArray("Message One");
			statefulSigner.update(mes1, 0, mes1.Length);
			byte[] sig1 = statefulSigner.generateSignature();

			isTrue(privKey.isUsed());

			byte[] mes2 = Strings.toByteArray("Message Two");
			statefulSigner.update(mes2, 0, mes2.Length);
			byte[] sig2 = statefulSigner.generateSignature();

			GMSSPrivateKeyParameters recoveredKey = (GMSSPrivateKeyParameters)statefulSigner.getUpdatedPrivateKey();

			isTrue(recoveredKey.isUsed() == false);

			try
			{
				statefulSigner.generateSignature();
			}
			catch (IllegalStateException e)
			{
				isEquals("signing key no longer usable", e.getMessage());
			}

			statefulSigner.init(false, pub);
			statefulSigner.update(mes2, 0, mes2.Length);
			if (!statefulSigner.verifySignature(sig2))
			{
				fail("verification two fails");
			}

			statefulSigner.update(mes1, 0, mes1.Length);
			if (!statefulSigner.verifySignature(sig1))
			{
				fail("verification one fails");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new GMSSSignerTest());
		}
	}

}