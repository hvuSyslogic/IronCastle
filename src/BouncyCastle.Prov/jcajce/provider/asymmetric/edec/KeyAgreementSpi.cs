using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using DerivationFunction = org.bouncycastle.crypto.DerivationFunction;
	using RawAgreement = org.bouncycastle.crypto.RawAgreement;
	using X25519Agreement = org.bouncycastle.crypto.agreement.X25519Agreement;
	using X448Agreement = org.bouncycastle.crypto.agreement.X448Agreement;
	using XDHUnifiedAgreement = org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
	using ConcatenationKDFGenerator = org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using X448PrivateKeyParameters = org.bouncycastle.crypto.@params.X448PrivateKeyParameters;
	using XDHUPrivateParameters = org.bouncycastle.crypto.@params.XDHUPrivateParameters;
	using XDHUPublicParameters = org.bouncycastle.crypto.@params.XDHUPublicParameters;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using BaseAgreementSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
	using DHUParameterSpec = org.bouncycastle.jcajce.spec.DHUParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

	public class KeyAgreementSpi : BaseAgreementSpi
	{
		private RawAgreement agreement;
		private DHUParameterSpec dhuSpec;
		private byte[] result;

		public KeyAgreementSpi(string algorithm) : base(algorithm, null)
		{
		}

		public KeyAgreementSpi(string algorithm, DerivationFunction kdf) : base(algorithm, kdf)
		{
		}

		public override byte[] calcSecret()
		{
			return result;
		}

		public override void engineInit(Key key, SecureRandom secureRandom)
		{
			if (key is BCXDHPrivateKey)
			{
				AsymmetricKeyParameter priv = ((BCXDHPrivateKey)key).engineGetKeyParameters();

				if (priv is X448PrivateKeyParameters)
				{
					agreement = getAgreement("X448");
				}
				else
				{
					agreement = getAgreement("X25519");
				}

				agreement.init(priv);
			}
			else
			{
				throw new InvalidKeyException("cannot identify XDH private key");
			}

			if (kdf != null)
			{
				ukmParameters = new byte[0];
			}
			else
			{
				ukmParameters = null;
			}
		}

		public override void engineInit(Key key, AlgorithmParameterSpec @params, SecureRandom secureRandom)
		{
			AsymmetricKeyParameter priv;

			if (key is BCXDHPrivateKey)
			{
				priv = ((BCXDHPrivateKey)key).engineGetKeyParameters();

				if (priv is X448PrivateKeyParameters)
				{
					agreement = getAgreement("X448");
				}
				else
				{
					agreement = getAgreement("X25519");
				}
			}
			else
			{
				throw new InvalidKeyException("cannot identify XDH private key");
			}

			ukmParameters = null;
			if (@params is DHUParameterSpec)
			{
				if (kaAlgorithm.IndexOf('U') < 0)
				{
					throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
				}

				dhuSpec = (DHUParameterSpec)@params;

				ukmParameters = dhuSpec.getUserKeyingMaterial();

				agreement.init(new XDHUPrivateParameters(priv, ((BCXDHPrivateKey)dhuSpec.getEphemeralPrivateKey()).engineGetKeyParameters(), ((BCXDHPublicKey)dhuSpec.getEphemeralPublicKey()).engineGetKeyParameters()));
			}
			else
			{
				agreement.init(priv);

				if (@params is UserKeyingMaterialSpec)
				{
					if (kdf == null)
					{
						throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
					}
					this.ukmParameters = ((UserKeyingMaterialSpec)@params).getUserKeyingMaterial();
				}
				else
				{
					throw new InvalidAlgorithmParameterException("unknown ParameterSpec");
				}
			}

			if (kdf != null && ukmParameters == null)
			{
				ukmParameters = new byte[0];
			}
		}

		public override Key engineDoPhase(Key key, bool lastPhase)
		{
			if (agreement == null)
			{
				throw new IllegalStateException(kaAlgorithm + " not initialised.");
			}

			if (!lastPhase)
			{
				throw new IllegalStateException(kaAlgorithm + " can only be between two parties.");
			}

			if (!(key is BCXDHPublicKey))
			{
				throw new InvalidKeyException("cannot identify XDH private key");
			}

			AsymmetricKeyParameter pub = ((BCXDHPublicKey)key).engineGetKeyParameters();

			result = new byte[agreement.getAgreementSize()];

			if (dhuSpec != null)
			{
				agreement.calculateAgreement(new XDHUPublicParameters(pub, ((BCXDHPublicKey)dhuSpec.getOtherPartyEphemeralKey()).engineGetKeyParameters()), result, 0);
			}
			else
			{
				agreement.calculateAgreement(pub, result, 0);
			}

			return null;
		}

		private RawAgreement getAgreement(string alg)
		{
			if (!(kaAlgorithm.Equals("XDH") || kaAlgorithm.StartsWith(alg, StringComparison.Ordinal)))
			{
				throw new InvalidKeyException("inappropriate key for " + kaAlgorithm);
			}

			if (kaAlgorithm.IndexOf('U') > 0)
			{
				if (alg.StartsWith("X448", StringComparison.Ordinal))
				{
					return new XDHUnifiedAgreement(new X448Agreement());
				}
				else
				{
					return new XDHUnifiedAgreement(new X25519Agreement());
				}
			}
			else
			{
				if (alg.StartsWith("X448", StringComparison.Ordinal))
				{
					return new X448Agreement();
				}
				else
				{
					return new X25519Agreement();
				}
			}
		}

		public sealed class XDH : KeyAgreementSpi
		{
			public XDH() : base("XDH")
			{
			}
		}

		public sealed class X448 : KeyAgreementSpi
		{
			public X448() : base("X448")
			{
			}
		}

		public sealed class X25519 : KeyAgreementSpi
		{
			public X25519() : base("X25519")
			{
			}
		}

		public sealed class X25519withSHA256CKDF : KeyAgreementSpi
		{
			public X25519withSHA256CKDF() : base("X25519withSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public sealed class X448withSHA512CKDF : KeyAgreementSpi
		{
			public X448withSHA512CKDF() : base("X448withSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public sealed class X25519withSHA256KDF : KeyAgreementSpi
		{
			public X25519withSHA256KDF() : base("X25519withSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public sealed class X448withSHA512KDF : KeyAgreementSpi
		{
			public X448withSHA512KDF() : base("X448withSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class X25519UwithSHA256CKDF : KeyAgreementSpi
		{
			public X25519UwithSHA256CKDF() : base("X25519UwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class X448UwithSHA512CKDF : KeyAgreementSpi
		{
			public X448UwithSHA512CKDF() : base("X448UwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class X25519UwithSHA256KDF : KeyAgreementSpi
		{
			public X25519UwithSHA256KDF() : base("X25519UwithSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class X448UwithSHA512KDF : KeyAgreementSpi
		{
			public X448UwithSHA512KDF() : base("X448UwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}
	}

}