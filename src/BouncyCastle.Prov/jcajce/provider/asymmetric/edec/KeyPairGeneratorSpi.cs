using org.bouncycastle.asn1.edec;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using Ed25519KeyPairGenerator = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
	using Ed448KeyPairGenerator = org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
	using X25519KeyPairGenerator = org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
	using X448KeyPairGenerator = org.bouncycastle.crypto.generators.X448KeyPairGenerator;
	using Ed25519KeyGenerationParameters = org.bouncycastle.crypto.@params.Ed25519KeyGenerationParameters;
	using Ed448KeyGenerationParameters = org.bouncycastle.crypto.@params.Ed448KeyGenerationParameters;
	using X25519KeyGenerationParameters = org.bouncycastle.crypto.@params.X25519KeyGenerationParameters;
	using X448KeyGenerationParameters = org.bouncycastle.crypto.@params.X448KeyGenerationParameters;
	using EdDSAParameterSpec = org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
	using XDHParameterSpec = org.bouncycastle.jcajce.spec.XDHParameterSpec;
	using ECNamedCurveGenParameterSpec = org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

	public class KeyPairGeneratorSpi : java.security.KeyPairGeneratorSpi
	{
		private const int EdDSA = -1;
		private const int XDH = -2;

		private const int Ed448 = 0;
		private const int Ed25519 = 1;
		private const int X448 = 2;
		private const int X25519 = 3;

		private int algorithm;
		private AsymmetricCipherKeyPairGenerator generator;

		private bool initialised;
		private SecureRandom secureRandom;

		public KeyPairGeneratorSpi(int algorithm, AsymmetricCipherKeyPairGenerator generator)
		{
			this.algorithm = algorithm;
			this.generator = generator;
		}

		public virtual void initialize(int strength, SecureRandom secureRandom)
		{
			this.secureRandom = secureRandom;

			switch (strength)
			{
			case 255:
			case 256:
				switch (algorithm)
				{
				case EdDSA:
				case Ed25519:
					setupGenerator(Ed25519);
					break;
				case XDH:
				case X25519:
					setupGenerator(X25519);
					break;
				default:
					throw new InvalidParameterException("key size not configurable");
				}
				break;
			case 448:
				switch (algorithm)
				{
				case EdDSA:
				case Ed448:
					setupGenerator(Ed448);
					break;
				case XDH:
				case X448:
					setupGenerator(X448);
					break;
				default:
					throw new InvalidParameterException("key size not configurable");
				}
				break;
			default:
				throw new InvalidParameterException("unknown key size");
			}
		}

		public virtual void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
		{
			this.secureRandom = secureRandom;

			if (paramSpec is ECGenParameterSpec)
			{
				initializeGenerator(((ECGenParameterSpec)paramSpec).getName());
			}
			else if (paramSpec is ECNamedCurveGenParameterSpec)
			{
				initializeGenerator(((ECNamedCurveGenParameterSpec)paramSpec).getName());
			}
			else if (paramSpec is EdDSAParameterSpec)
			{
				initializeGenerator(((EdDSAParameterSpec)paramSpec).getCurveName());
			}
			else if (paramSpec is XDHParameterSpec)
			{
				initializeGenerator(((XDHParameterSpec)paramSpec).getCurveName());
			}
			else
			{
				throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + paramSpec);
			}
		}

		private void algorithmCheck(int algorithm)
		{
			if (this.algorithm != algorithm)
			{
				if (this.algorithm == Ed25519 || this.algorithm == Ed448)
				{
					throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
				}
				if (this.algorithm == EdDSA && (algorithm != Ed25519 && algorithm != Ed448))
				{
					throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
				}
				if (this.algorithm == X25519 || this.algorithm == X448)
				{
					throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
				}
				if (this.algorithm == XDH && (algorithm != X25519 && algorithm != X448))
				{
					throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
				}
				this.algorithm = algorithm;
			}
		}

		private void initializeGenerator(string name)
		{
			if (name.Equals(EdDSAParameterSpec.Ed448, StringComparison.OrdinalIgnoreCase) || name.Equals(EdECObjectIdentifiers_Fields.id_Ed448.getId()))
			{
				algorithmCheck(Ed448);
				this.generator = new Ed448KeyPairGenerator();
				setupGenerator(Ed448);
			}
			else if (name.Equals(EdDSAParameterSpec.Ed25519, StringComparison.OrdinalIgnoreCase) || name.Equals(EdECObjectIdentifiers_Fields.id_Ed25519.getId()))
			{
				algorithmCheck(Ed25519);
				this.generator = new Ed25519KeyPairGenerator();
				setupGenerator(Ed25519);
			}
			else if (name.Equals(XDHParameterSpec.X448, StringComparison.OrdinalIgnoreCase) || name.Equals(EdECObjectIdentifiers_Fields.id_X448.getId()))
			{
				algorithmCheck(X448);
				this.generator = new X448KeyPairGenerator();
				setupGenerator(X448);
			}
			else if (name.Equals(XDHParameterSpec.X25519, StringComparison.OrdinalIgnoreCase) || name.Equals(EdECObjectIdentifiers_Fields.id_X25519.getId()))
			{
				algorithmCheck(X25519);
				this.generator = new X25519KeyPairGenerator();
				setupGenerator(X25519);
			}
		}

		public virtual KeyPair generateKeyPair()
		{
			if (generator == null)
			{
				throw new IllegalStateException("generator not correctly initialized");
			}

			if (!initialised)
			{
				setupGenerator(algorithm);
			}

			AsymmetricCipherKeyPair kp = generator.generateKeyPair();

			switch (algorithm)
			{
			case Ed448:
				return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
			case Ed25519:
				return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
			case X448:
				return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
			case X25519:
				return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
			}

			throw new IllegalStateException("generator not correctly initialized");
		}

		private void setupGenerator(int algorithm)
		{
			initialised = true;

			if (secureRandom == null)
			{
				secureRandom = new SecureRandom();
			}

			switch (algorithm)
			{
			case Ed448:
				generator.init(new Ed448KeyGenerationParameters(secureRandom));
				break;
			case EdDSA:
			case Ed25519:
				generator.init(new Ed25519KeyGenerationParameters(secureRandom));
				break;
			case X448:
				generator.init(new X448KeyGenerationParameters(secureRandom));
				break;
			case XDH:
			case X25519:
				generator.init(new X25519KeyGenerationParameters(secureRandom));
				break;
			}
		}

		public sealed class EdDSA : KeyPairGeneratorSpi
		{
			public EdDSA() : base(EdDSA, null)
			{
			}
		}

		public sealed class Ed448 : KeyPairGeneratorSpi
		{
			public Ed448() : base(Ed448, new Ed448KeyPairGenerator())
			{
			}
		}

		public sealed class Ed25519 : KeyPairGeneratorSpi
		{
			public Ed25519() : base(Ed25519, new Ed25519KeyPairGenerator())
			{
			}
		}

		public sealed class XDH : KeyPairGeneratorSpi
		{
			public XDH() : base(XDH, null)
			{
			}
		}

		public sealed class X448 : KeyPairGeneratorSpi
		{
			public X448() : base(X448, new X448KeyPairGenerator())
			{
			}
		}

		public sealed class X25519 : KeyPairGeneratorSpi
		{
			public X25519() : base(X25519, new X25519KeyPairGenerator())
			{
			}
		}
	}

}