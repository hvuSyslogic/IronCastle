namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DSTU4145NamedCurves = org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using DSTU4145KeyPairGenerator = org.bouncycastle.crypto.generators.DSTU4145KeyPairGenerator;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using DSTU4145Parameters = org.bouncycastle.crypto.@params.DSTU4145Parameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using DSTU4145ParameterSpec = org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		internal object ecParams = null;
		internal ECKeyPairGenerator engine = new DSTU4145KeyPairGenerator();

		internal string algorithm = "DSTU4145";
		internal ECKeyGenerationParameters param;
		//int strength = 239;
		internal SecureRandom random = null;
		internal bool initialised = false;

		public KeyPairGeneratorSpi() : base("DSTU4145")
		{
		}

		public virtual void initialize(int strength, SecureRandom random)
		{
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

				if (p is DSTU4145ParameterSpec)
				{
					DSTU4145ParameterSpec dstuSpec = (DSTU4145ParameterSpec)p;

					param = new ECKeyGenerationParameters(new DSTU4145Parameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), dstuSpec.getDKE()), random);
				}
				else
				{
					param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);
				}
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

				//ECDomainParameters ecP = ECGOST3410NamedCurves.getByName(curveName);
				ECDomainParameters ecP = DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier(curveName));
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
				throw new IllegalStateException("DSTU Key Pair Generator not initialised");
			}

			AsymmetricCipherKeyPair pair = engine.generateKeyPair();
			ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

			if (ecParams is ECParameterSpec)
			{
				ECParameterSpec p = (ECParameterSpec)ecParams;

				BCDSTU4145PublicKey pubKey = new BCDSTU4145PublicKey(algorithm, pub, p);
				return new KeyPair(pubKey, new BCDSTU4145PrivateKey(algorithm, priv, pubKey, p));
			}
			else if (ecParams == null)
			{
				return new KeyPair(new BCDSTU4145PublicKey(algorithm, pub), new BCDSTU4145PrivateKey(algorithm, priv));
			}
			else
			{
				java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

				BCDSTU4145PublicKey pubKey = new BCDSTU4145PublicKey(algorithm, pub, p);

				return new KeyPair(pubKey, new BCDSTU4145PrivateKey(algorithm, priv, pubKey, p));
			}
		}
	}


}