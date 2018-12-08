namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost
{

	using ECGOST3410NamedCurves = org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal object ecParams = null;
		internal ECKeyPairGenerator engine = new ECKeyPairGenerator();

		internal string algorithm = "ECGOST3410";
		internal ECKeyGenerationParameters param;
		internal int strength = 239;
		internal SecureRandom random = null;
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("ECGOST3410")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
			this.strength = strength;
			this.random = random;

			if (ecParams != null)
			{
				try
				{
					initialize((ECGenParameterSpec)ecParams, random);
				}
				catch (InvalidAlgorithmParameterException)
				{
					throw new InvalidParameterException("key size not configurable.");
				}
			}
			else
			{
				throw new InvalidParameterException("unknown key size.");
			}
		}

		public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (@params is ECParameterSpec)
			{
				ECParameterSpec p = (ECParameterSpec)@params;
				this.ecParams = @params;

				param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

				engine.init(param);
				initialised = true;
			}
			else if (@params is java.security.spec.ECParameterSpec)
			{
				java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)@params;
				this.ecParams = @params;

				ECCurve curve = EC5Util.convertCurve(p.getCurve());
				ECPoint g = EC5Util.convertPoint(curve, p.getGenerator(), false);

				param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);

				engine.init(param);
				initialised = true;
			}
			else if (@params is ECGenParameterSpec || @params is ECNamedCurveGenParameterSpec)
			{
				string curveName;

				if (@params is ECGenParameterSpec)
				{
					curveName = ((ECGenParameterSpec)@params).getName();
				}
				else
				{
					curveName = ((ECNamedCurveGenParameterSpec)@params).getName();
				}

				ECDomainParameters ecP = ECGOST3410NamedCurves.getByName(curveName);
				if (ecP == null)
				{
					throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
				}

				this.ecParams = new ECNamedCurveSpec(curveName, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());

				java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

				ECCurve curve = EC5Util.convertCurve(p.getCurve());
				ECPoint g = EC5Util.convertPoint(curve, p.getGenerator(), false);

				param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);

				engine.init(param);
				initialised = true;
			}
			else if (@params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() != null)
			{
				ECParameterSpec p = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
				this.ecParams = @params;

				param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

				engine.init(param);
				initialised = true;
			}
			else if (@params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() == null)
			{
				throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
			}
			else
			{
				throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec: " + @params.GetType().getName());
			}
		}

		public virtual KeyPair generateKeyPair()
		{
			if (!initialised)
			{
				throw new IllegalStateException("EC Key Pair Generator not initialised");
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

			if (ecParams is ECParameterSpec)
			{
				ECParameterSpec p = (ECParameterSpec)ecParams;

				BCECGOST3410PublicKey pubKey = new BCECGOST3410PublicKey(algorithm, pub, p);
				return new KeyPair(pubKey, new BCECGOST3410PrivateKey(algorithm, priv, pubKey, p));
			}
			else if (ecParams == null)
			{
				return new KeyPair(new BCECGOST3410PublicKey(algorithm, pub), new BCECGOST3410PrivateKey(algorithm, priv));
			}
			else
			{
				java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

				BCECGOST3410PublicKey pubKey = new BCECGOST3410PublicKey(algorithm, pub, p);

				return new KeyPair(pubKey, new BCECGOST3410PrivateKey(algorithm, priv, pubKey, p));
			}
		}
	}


}