namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using ECKeyPairGenerator = org.bouncycastle.crypto.generators.ECKeyPairGenerator;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECKeyGenerationParameters = org.bouncycastle.crypto.@params.ECKeyGenerationParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
	using ECNamedCurveSpec = org.bouncycastle.jce.spec.ECNamedCurveSpec;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Integers = org.bouncycastle.util.Integers;

	public abstract class KeyPairGeneratorSpi : java.security.KeyPairGenerator
	{
		public KeyPairGeneratorSpi(string algorithmName) : base(algorithmName)
		{
		}

		public class EC : KeyPairGeneratorSpi
		{
			internal ECKeyGenerationParameters param;
			internal ECKeyPairGenerator engine = new ECKeyPairGenerator();
			internal object ecParams = null;
			internal int strength = 239;
			internal SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
			internal bool initialised = false;
			internal string algorithm;
			internal ProviderConfiguration configuration;

			internal static Hashtable ecParameters;

			static EC()
			{
				ecParameters = new Hashtable();

				ecParameters.put(Integers.valueOf(192), new ECGenParameterSpec("prime192v1")); // a.k.a P-192
				ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec("prime239v1"));
				ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec("prime256v1")); // a.k.a P-256

				ecParameters.put(Integers.valueOf(224), new ECGenParameterSpec("P-224"));
				ecParameters.put(Integers.valueOf(384), new ECGenParameterSpec("P-384"));
				ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec("P-521"));
			}

			public EC() : base("EC")
			{
				this.algorithm = "EC";
				this.configuration = BouncyCastleProvider.CONFIGURATION;
			}

			public EC(string algorithm, ProviderConfiguration configuration) : base(algorithm)
			{
				this.algorithm = algorithm;
				this.configuration = configuration;
			}

			public virtual void initialize(int strength, SecureRandom random)
			{
				this.strength = strength;
				this.random = random;

				ECGenParameterSpec ecParams = (ECGenParameterSpec)ecParameters.get(Integers.valueOf(strength));
				if (ecParams == null)
				{
					throw new InvalidParameterException("unknown key size.");
				}

				try
				{
					initialize(ecParams, random);
				}
				catch (InvalidAlgorithmParameterException)
				{
					throw new InvalidParameterException("key size not configurable.");
				}
			}

			public virtual void initialize(AlgorithmParameterSpec @params, SecureRandom random)
			{
				if (@params == null)
				{
					ECParameterSpec implicitCA = configuration.getEcImplicitlyCa();
					if (implicitCA == null)
					{
						throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
					}

					this.ecParams = null;
					this.param = createKeyGenParamsBC(implicitCA, random);
				}
				else if (@params is ECParameterSpec)
				{
					this.ecParams = @params;
					this.param = createKeyGenParamsBC((ECParameterSpec)@params, random);
				}
				else if (@params is java.security.spec.ECParameterSpec)
				{
					this.ecParams = @params;
					this.param = createKeyGenParamsJCE((java.security.spec.ECParameterSpec)@params, random);
				}
				else if (@params is ECGenParameterSpec)
				{
					initializeNamedCurve(((ECGenParameterSpec)@params).getName(), random);
				}
				else if (@params is ECNamedCurveGenParameterSpec)
				{
					initializeNamedCurve(((ECNamedCurveGenParameterSpec)@params).getName(), random);
				}
				else
				{
					throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec");
				}

				engine.init(param);
				initialised = true;
			}

			public virtual KeyPair generateKeyPair()
			{
				if (!initialised)
				{
					initialize(strength, new SecureRandom());
				}

				AsymmetricCipherKeyPair pair = engine.generateKeyPair();
				ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
				ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

				if (ecParams is ECParameterSpec)
				{
					ECParameterSpec p = (ECParameterSpec)ecParams;

					BCECPublicKey pubKey = new BCECPublicKey(algorithm, pub, p, configuration);
					return new KeyPair(pubKey, new BCECPrivateKey(algorithm, priv, pubKey, p, configuration));
				}
				else if (ecParams == null)
				{
				   return new KeyPair(new BCECPublicKey(algorithm, pub, configuration), new BCECPrivateKey(algorithm, priv, configuration));
				}
				else
				{
					java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

					BCECPublicKey pubKey = new BCECPublicKey(algorithm, pub, p, configuration);

					return new KeyPair(pubKey, new BCECPrivateKey(algorithm, priv, pubKey, p, configuration));
				}
			}

			public virtual ECKeyGenerationParameters createKeyGenParamsBC(ECParameterSpec p, SecureRandom r)
			{
				return new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), r);
			}

			public virtual ECKeyGenerationParameters createKeyGenParamsJCE(java.security.spec.ECParameterSpec p, SecureRandom r)
			{
				ECCurve curve = EC5Util.convertCurve(p.getCurve());
				ECPoint g = EC5Util.convertPoint(curve, p.getGenerator(), false);
				BigInteger n = p.getOrder();
				BigInteger h = BigInteger.valueOf(p.getCofactor());
				ECDomainParameters dp = new ECDomainParameters(curve, g, n, h);
				return new ECKeyGenerationParameters(dp, r);
			}

			public virtual ECNamedCurveSpec createNamedCurveSpec(string curveName)
			{
				// NOTE: Don't bother with custom curves here as the curve will be converted to JCE type shortly

				X9ECParameters p = ECUtils.getDomainParametersFromName(curveName);
				if (p == null)
				{
					try
					{
						// Check whether it's actually an OID string (SunJSSE ServerHandshaker setupEphemeralECDHKeys bug)
						p = ECNamedCurveTable.getByOID(new ASN1ObjectIdentifier(curveName));
						if (p == null)
						{
							Map extraCurves = configuration.getAdditionalECParameters();

							p = (X9ECParameters)extraCurves.get(new ASN1ObjectIdentifier(curveName));

							if (p == null)
							{
								throw new InvalidAlgorithmParameterException("unknown curve OID: " + curveName);
							}
						}
					}
					catch (IllegalArgumentException)
					{
						throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
					}
				}

				// Work-around for JDK bug -- it won't look up named curves properly if seed is present
				byte[] seed = null; //p.getSeed();

				return new ECNamedCurveSpec(curveName, p.getCurve(), p.getG(), p.getN(), p.getH(), seed);
			}

			public virtual void initializeNamedCurve(string curveName, SecureRandom random)
			{
				ECNamedCurveSpec namedCurve = createNamedCurveSpec(curveName);
				this.ecParams = namedCurve;
				this.param = createKeyGenParamsJCE(namedCurve, random);
			}
		}

		public class ECDSA : EC
		{
			public ECDSA() : base("ECDSA", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECDH : EC
		{
			public ECDH() : base("ECDH", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECDHC : EC
		{
			public ECDHC() : base("ECDHC", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECMQV : EC
		{
			public ECMQV() : base("ECMQV", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}
	}
}