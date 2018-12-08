using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost12
{

	using X9IntegerConverter = org.bouncycastle.asn1.x9.X9IntegerConverter;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DerivationFunction = org.bouncycastle.crypto.DerivationFunction;
	using ECVKOAgreement = org.bouncycastle.crypto.agreement.ECVKOAgreement;
	using GOST3411_2012_256Digest = org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
	using GOST3411_2012_512Digest = org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ParametersWithUKM = org.bouncycastle.crypto.@params.ParametersWithUKM;
	using BaseAgreementSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
	using ECPrivateKey = org.bouncycastle.jce.interfaces.ECPrivateKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;

	public class KeyAgreementSpi : BaseAgreementSpi
	{
		private static readonly X9IntegerConverter converter = new X9IntegerConverter();

		private new string kaAlgorithm;

		private ECDomainParameters parameters;
		private ECVKOAgreement agreement;

		private byte[] result;

		public KeyAgreementSpi(string kaAlgorithm, ECVKOAgreement agreement, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{

			this.kaAlgorithm = kaAlgorithm;
			this.agreement = agreement;
		}

		public override Key engineDoPhase(Key key, bool lastPhase)
		{
			if (parameters == null)
			{
				throw new IllegalStateException(kaAlgorithm + " not initialised.");
			}

			if (!lastPhase)
			{
				throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
			}

			CipherParameters pubKey;
			{
				if (!(key is PublicKey))
				{
					throw new InvalidKeyException(kaAlgorithm + " key agreement requires " + getSimpleName(typeof(ECPublicKey)) + " for doPhase");
				}

				pubKey = generatePublicKeyParameter((PublicKey)key);
			}

			try
			{
				result = agreement.calculateAgreement(pubKey);
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final Exception e)
			catch (Exception e)
			{
				throw new InvalidKeyExceptionAnonymousInnerClass(this, "calculation failed: " + e.getMessage(), e);
			}

			return null;
		}

		public class InvalidKeyExceptionAnonymousInnerClass : InvalidKeyException
		{
			private readonly KeyAgreementSpi outerInstance;

			private ception e;

			public InvalidKeyExceptionAnonymousInnerClass(KeyAgreementSpi outerInstance, string getMessage, ception e) : base(getMessage)
			{
				this.outerInstance = outerInstance;
				this.e = e;
			}

			public Exception getCause()
			{
							return e;
			}
		}

		public override void engineInit(Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (@params != null && !(@params is UserKeyingMaterialSpec))
			{
				throw new InvalidAlgorithmParameterException("No algorithm parameters supported");
			}

			initFromKey(key, @params);
		}

		public override void engineInit(Key key, SecureRandom random)
		{
			initFromKey(key, null);
		}

		private void initFromKey(Key key, AlgorithmParameterSpec parameterSpec)
		{
			{
				if (!(key is PrivateKey))
				{
					throw new InvalidKeyException(kaAlgorithm + " key agreement requires " + getSimpleName(typeof(ECPrivateKey)) + " for initialisation");
				}

				ECPrivateKeyParameters privKey = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter((PrivateKey)key);
				this.parameters = privKey.getParameters();
				ukmParameters = (parameterSpec is UserKeyingMaterialSpec) ? ((UserKeyingMaterialSpec)parameterSpec).getUserKeyingMaterial() : null;
				agreement.init(new ParametersWithUKM(privKey, ukmParameters));
			}
		}

		private static string getSimpleName(Class clazz)
		{
			string fullName = clazz.getName();

			return fullName.Substring(fullName.LastIndexOf('.') + 1);
		}

		internal static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			return (key is BCECGOST3410_2012PublicKey) ? ((BCECGOST3410_2012PublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
		}

		public override byte[] calcSecret()
		{
			return result;
		}

		public class ECVKO256 : KeyAgreementSpi
		{
			public ECVKO256() : base("ECGOST3410-2012-256", new ECVKOAgreement(new GOST3411_2012_256Digest()), null)
			{
			}
		}

		public class ECVKO512 : KeyAgreementSpi
		{
			public ECVKO512() : base("ECGOST3410-2012-512", new ECVKOAgreement(new GOST3411_2012_512Digest()), null)
			{
			}
		}
	}

}