using org.bouncycastle.asn1.sec;
using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ec
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using OpenSSHPublicKeyUtil = org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using EC5Util = org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
	using ProviderConfiguration = org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;
	using ECPrivateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec;
	using ECPublicKeySpec = org.bouncycastle.jce.spec.ECPublicKeySpec;
	using OpenSSHPrivateKeySpec = org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec;
	using OpenSSHPublicKeySpec = org.bouncycastle.jce.spec.OpenSSHPublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi, AsymmetricKeyInfoConverter
	{
		internal string algorithm;
		internal ProviderConfiguration configuration;

		public KeyFactorySpi(string algorithm, ProviderConfiguration configuration)
		{
			this.algorithm = algorithm;
			this.configuration = configuration;
		}

		public virtual Key engineTranslateKey(Key key)
		{
			if (key is ECPublicKey)
			{
				return new BCECPublicKey((ECPublicKey)key, configuration);
			}
			else if (key is ECPrivateKey)
			{
				return new BCECPrivateKey((ECPrivateKey)key, configuration);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(java.security.spec.ECPublicKeySpec)) && key is ECPublicKey)
			{
				ECPublicKey k = (ECPublicKey)key;
				if (k.getParams() != null)
				{
					return new java.security.spec.ECPublicKeySpec(k.getW(), k.getParams());
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new java.security.spec.ECPublicKeySpec(k.getW(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
				}
			}
			else if (spec.isAssignableFrom(typeof(java.security.spec.ECPrivateKeySpec)) && key is ECPrivateKey)
			{
				ECPrivateKey k = (ECPrivateKey)key;

				if (k.getParams() != null)
				{
					return new java.security.spec.ECPrivateKeySpec(k.getS(), k.getParams());
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new java.security.spec.ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(EC5Util.convertCurve(implicitSpec.getCurve(), implicitSpec.getSeed()), implicitSpec));
				}
			}
			else if (spec.isAssignableFrom(typeof(ECPublicKeySpec)) && key is ECPublicKey)
			{
				ECPublicKey k = (ECPublicKey)key;
				if (k.getParams() != null)
				{
					return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW(), false), EC5Util.convertSpec(k.getParams(), false));
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new ECPublicKeySpec(EC5Util.convertPoint(k.getParams(), k.getW(), false), implicitSpec);
				}
			}
			else if (spec.isAssignableFrom(typeof(ECPrivateKeySpec)) && key is ECPrivateKey)
			{
				ECPrivateKey k = (ECPrivateKey)key;

				if (k.getParams() != null)
				{
					return new ECPrivateKeySpec(k.getS(), EC5Util.convertSpec(k.getParams(), false));
				}
				else
				{
					ECParameterSpec implicitSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();

					return new ECPrivateKeySpec(k.getS(), implicitSpec);
				}
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPublicKeySpec)) && key is ECPublicKey)
			{
				if (key is BCECPublicKey)
				{
					BCECPublicKey bcPk = (BCECPublicKey)key;
					ECParameterSpec sc = bcPk.getParameters();
					try
					{
						return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new ECPublicKeyParameters(bcPk.getQ(), new ECDomainParameters(sc.getCurve(), sc.getG(), sc.getN(), sc.getH(), sc.getSeed()))));
					}
					catch (IOException e)
					{
						throw new IllegalArgumentException("unable to produce encoding: " + e.Message);
					}
				}
				else
				{
					throw new IllegalArgumentException("invalid key type: " + key.GetType().getName());
				}
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPrivateKeySpec)) && key is ECPrivateKey)
			{
				if (key is BCECPrivateKey)
				{
					try
					{
						return new OpenSSHPrivateKeySpec(PrivateKeyInfo.getInstance(key.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
					}
					catch (IOException e)
					{
						throw new IllegalArgumentException("cannot encoded key: " + e.Message);
					}
				}
				else
				{
					throw new IllegalArgumentException("invalid key type: " + key.GetType().getName());
				}

			}

			return base.engineGetKeySpec(key, spec);
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is ECPrivateKeySpec)
			{
				return new BCECPrivateKey(algorithm, (ECPrivateKeySpec)keySpec, configuration);
			}
			else if (keySpec is java.security.spec.ECPrivateKeySpec)
			{
				return new BCECPrivateKey(algorithm, (java.security.spec.ECPrivateKeySpec)keySpec, configuration);
			}
			else if (keySpec is OpenSSHPrivateKeySpec)
			{
				ECPrivateKey ecKey = ECPrivateKey.getInstance(((OpenSSHPrivateKeySpec)keySpec).getEncoded());

				try
				{
					return new BCECPrivateKey(algorithm, new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_ecPublicKey, ecKey.getParameters()), ecKey), configuration);
				}
				catch (IOException e)
				{
					throw new InvalidKeySpecException("bad encoding: " + e.Message);
				}
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			try
			{
				if (keySpec is ECPublicKeySpec)
				{
					return new BCECPublicKey(algorithm, (ECPublicKeySpec)keySpec, configuration);
				}
				else if (keySpec is java.security.spec.ECPublicKeySpec)
				{
					return new BCECPublicKey(algorithm, (java.security.spec.ECPublicKeySpec)keySpec, configuration);
				}
				else if (keySpec is OpenSSHPublicKeySpec)
				{
					CipherParameters @params = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
					if (@params is ECPublicKeyParameters)
					{
						ECDomainParameters parameters = ((ECPublicKeyParameters)@params).getParameters();
						return engineGeneratePublic(new ECPublicKeySpec(((ECPublicKeyParameters)@params).getQ(), new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH(), parameters.getSeed())
						   ));
					}
					else
					{
						throw new IllegalArgumentException("openssh key is not ec public key");
					}
				}
			}
			catch (Exception e)
			{
				throw new InvalidKeySpecException("invalid KeySpec: " + e.Message, e);
			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (algOid.Equals(X9ObjectIdentifiers_Fields.id_ecPublicKey))
			{
				return new BCECPrivateKey(algorithm, keyInfo, configuration);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (algOid.Equals(X9ObjectIdentifiers_Fields.id_ecPublicKey))
			{
				return new BCECPublicKey(algorithm, keyInfo, configuration);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public class EC : KeyFactorySpi
		{
			public EC() : base("EC", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECDSA : KeyFactorySpi
		{
			public ECDSA() : base("ECDSA", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECGOST3410 : KeyFactorySpi
		{
			public ECGOST3410() : base("ECGOST3410", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECGOST3410_2012 : KeyFactorySpi
		{
			public ECGOST3410_2012() : base("ECGOST3410-2012", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECDH : KeyFactorySpi
		{
			public ECDH() : base("ECDH", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECDHC : KeyFactorySpi
		{
			public ECDHC() : base("ECDHC", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}

		public class ECMQV : KeyFactorySpi
		{
			public ECMQV() : base("ECMQV", BouncyCastleProvider.CONFIGURATION)
			{
			}
		}
	}
}