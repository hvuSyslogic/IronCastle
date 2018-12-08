namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{


	using BasicAgreement = org.bouncycastle.crypto.BasicAgreement;
	using DerivationFunction = org.bouncycastle.crypto.DerivationFunction;
	using DHUnifiedAgreement = org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
	using MQVBasicAgreement = org.bouncycastle.crypto.agreement.MQVBasicAgreement;
	using ConcatenationKDFGenerator = org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
	using DHKEKGenerator = org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using DHMQVPrivateParameters = org.bouncycastle.crypto.@params.DHMQVPrivateParameters;
	using DHMQVPublicParameters = org.bouncycastle.crypto.@params.DHMQVPublicParameters;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using DHUPrivateParameters = org.bouncycastle.crypto.@params.DHUPrivateParameters;
	using DHUPublicParameters = org.bouncycastle.crypto.@params.DHUPublicParameters;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using BaseAgreementSpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
	using DHDomainParameterSpec = org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
	using DHUParameterSpec = org.bouncycastle.jcajce.spec.DHUParameterSpec;
	using MQVParameterSpec = org.bouncycastle.jcajce.spec.MQVParameterSpec;
	using UserKeyingMaterialSpec = org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

	/// <summary>
	/// Diffie-Hellman key agreement. There's actually a better way of doing this
	/// if you are using long term public keys, see the light-weight version for
	/// details.
	/// </summary>
	public class KeyAgreementSpi : BaseAgreementSpi
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		private readonly DHUnifiedAgreement unifiedAgreement;
		private readonly BasicAgreement mqvAgreement;

		private DHUParameterSpec dheParameters;
		private MQVParameterSpec mqvParameters;

		private BigInteger x;
		private BigInteger p;
		private BigInteger g;

		private byte[] result;

		public KeyAgreementSpi() : this("Diffie-Hellman", null)
		{
		}

		public KeyAgreementSpi(string kaAlgorithm, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{
			this.unifiedAgreement = null;
			this.mqvAgreement = null;
		}

		public KeyAgreementSpi(string kaAlgorithm, DHUnifiedAgreement unifiedAgreement, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{
			this.unifiedAgreement = unifiedAgreement;
			this.mqvAgreement = null;
		}

		public KeyAgreementSpi(string kaAlgorithm, BasicAgreement mqvAgreement, DerivationFunction kdf) : base(kaAlgorithm, kdf)
		{
			this.unifiedAgreement = null;
			this.mqvAgreement = mqvAgreement;
		}

		public virtual byte[] bigIntToBytes(BigInteger r)
		{
			//
			// RFC 2631 (2.1.2) specifies that the secret should be padded with leading zeros if necessary
			// must be the same length as p
			//
			int expectedLength = (p.bitLength() + 7) / 8;

			byte[] tmp = r.toByteArray();

			if (tmp.Length == expectedLength)
			{
				return tmp;
			}

			if (tmp[0] == 0 && tmp.Length == expectedLength + 1)
			{
				byte[] rv = new byte[tmp.Length - 1];

				JavaSystem.arraycopy(tmp, 1, rv, 0, rv.Length);
				return rv;
			}

			// tmp must be shorter than expectedLength
			// pad to the left with zeros.
			byte[] rv = new byte[expectedLength];

			JavaSystem.arraycopy(tmp, 0, rv, rv.Length - tmp.Length, tmp.Length);

			return rv;
		}

		public override Key engineDoPhase(Key key, bool lastPhase)
		{
			if (x == null)
			{
				throw new IllegalStateException("Diffie-Hellman not initialised.");
			}

			if (!(key is DHPublicKey))
			{
				throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey");
			}
			DHPublicKey pubKey = (DHPublicKey)key;

			if (!pubKey.getParams().getG().Equals(g) || !pubKey.getParams().getP().Equals(p))
			{
				throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!");
			}

			BigInteger peerY = ((DHPublicKey)key).getY();
			if (peerY == null || peerY.compareTo(TWO) < 0 || peerY.compareTo(p.subtract(ONE)) >= 0)
			{
				throw new InvalidKeyException("Invalid DH PublicKey");
			}

			if (unifiedAgreement != null)
			{
				if (!lastPhase)
				{
					throw new IllegalStateException("unified Diffie-Hellman can use only two key pairs");
				}

				DHPublicKeyParameters staticKey = generatePublicKeyParameter((PublicKey)key);
				DHPublicKeyParameters ephemKey = generatePublicKeyParameter(dheParameters.getOtherPartyEphemeralKey());

				DHUPublicParameters pKey = new DHUPublicParameters(staticKey, ephemKey);

				result = unifiedAgreement.calculateAgreement(pKey);

				return null;
			}
			else if (mqvAgreement != null)
			{
				if (!lastPhase)
				{
					throw new IllegalStateException("MQV Diffie-Hellman can use only two key pairs");
				}

				DHPublicKeyParameters staticKey = generatePublicKeyParameter((PublicKey)key);
				DHPublicKeyParameters ephemKey = generatePublicKeyParameter(mqvParameters.getOtherPartyEphemeralKey());

				DHMQVPublicParameters pKey = new DHMQVPublicParameters(staticKey, ephemKey);

				result = bigIntToBytes(mqvAgreement.calculateAgreement(pKey));

				return null;
			}
			else
			{
				BigInteger res = peerY.modPow(x, p);
				if (res.compareTo(ONE) == 0)
				{
					throw new InvalidKeyException("Shared key can't be 1");
				}

				result = bigIntToBytes(res);

				if (lastPhase)
				{
					return null;
				}

				return new BCDHPublicKey(res, pubKey.getParams());
			}
		}

		public override byte[] engineGenerateSecret()
		{
			if (x == null)
			{
				throw new IllegalStateException("Diffie-Hellman not initialised.");
			}

			return base.engineGenerateSecret();
		}

		public override int engineGenerateSecret(byte[] sharedSecret, int offset)
		{
			if (x == null)
			{
				throw new IllegalStateException("Diffie-Hellman not initialised.");
			}

			return base.engineGenerateSecret(sharedSecret, offset);
		}

		public override SecretKey engineGenerateSecret(string algorithm)
		{
			if (x == null)
			{
				throw new IllegalStateException("Diffie-Hellman not initialised.");
			}

			// for JSSE compatibility
			if (algorithm.Equals("TlsPremasterSecret"))
			{
				return new SecretKeySpec(trimZeroes(result), algorithm);
			}

			return base.engineGenerateSecret(algorithm);
		}

		public override void engineInit(Key key, AlgorithmParameterSpec @params, SecureRandom random)
		{
			if (!(key is DHPrivateKey))
			{
				throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation");
			}
			DHPrivateKey privKey = (DHPrivateKey)key;

			if (@params != null)
			{
				if (@params is DHParameterSpec) // p, g override.
				{
					DHParameterSpec p = (DHParameterSpec)@params;

					this.p = p.getP();
					this.g = p.getG();
					this.dheParameters = null;
					this.ukmParameters = null;
				}
				else if (@params is DHUParameterSpec)
				{
					if (unifiedAgreement == null)
					{
						throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
					}
					this.p = privKey.getParams().getP();
					this.g = privKey.getParams().getG();
					this.dheParameters = (DHUParameterSpec)@params;
					this.ukmParameters = ((DHUParameterSpec)@params).getUserKeyingMaterial();

					if (dheParameters.getEphemeralPublicKey() != null)
					{
						unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey), generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(dheParameters.getEphemeralPublicKey())));
					}
					else
					{
						unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(privKey), generatePrivateKeyParameter(dheParameters.getEphemeralPrivateKey())));
					}
				}
				else if (@params is MQVParameterSpec)
				{
					if (mqvAgreement == null)
					{
						throw new InvalidAlgorithmParameterException("agreement algorithm not MQV based");
					}
					this.p = privKey.getParams().getP();
					this.g = privKey.getParams().getG();
					this.mqvParameters = (MQVParameterSpec)@params;
					this.ukmParameters = ((MQVParameterSpec)@params).getUserKeyingMaterial();

					if (mqvParameters.getEphemeralPublicKey() != null)
					{
						mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(privKey), generatePrivateKeyParameter(mqvParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(mqvParameters.getEphemeralPublicKey())));
					}
					else
					{
						mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(privKey), generatePrivateKeyParameter(mqvParameters.getEphemeralPrivateKey())));
					}
				}
				else if (@params is UserKeyingMaterialSpec)
				{
					if (kdf == null)
					{
						throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
					}
					this.p = privKey.getParams().getP();
					this.g = privKey.getParams().getG();
					this.dheParameters = null;
					this.ukmParameters = ((UserKeyingMaterialSpec)@params).getUserKeyingMaterial();
				}
				else
				{
					throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
				}
			}
			else
			{
				this.p = privKey.getParams().getP();
				this.g = privKey.getParams().getG();
			}

			this.x = privKey.getX();
			this.result = bigIntToBytes(x);
		}

		public override void engineInit(Key key, SecureRandom random)
		{
			if (!(key is DHPrivateKey))
			{
				throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey");
			}

			DHPrivateKey privKey = (DHPrivateKey)key;

			this.p = privKey.getParams().getP();
			this.g = privKey.getParams().getG();
			this.x = privKey.getX();
			this.result = bigIntToBytes(x);
		}

		public override byte[] calcSecret()
		{
			return result;
		}

		private DHPrivateKeyParameters generatePrivateKeyParameter(PrivateKey privKey)
		{
			if (privKey is DHPrivateKey)
			{
				if (privKey is BCDHPrivateKey)
				{
					return ((BCDHPrivateKey)privKey).engineGetKeyParameters();
				}
				else
				{
					DHPrivateKey pub = (DHPrivateKey)privKey;

					DHParameterSpec @params = pub.getParams();
					return new DHPrivateKeyParameters(pub.getX(), new DHParameters(@params.getP(), @params.getG(), null, @params.getL()));
				}
			}
			else
			{
				throw new InvalidKeyException("private key not a DHPrivateKey");
			}
		}

		private DHPublicKeyParameters generatePublicKeyParameter(PublicKey pubKey)
		{
			if (pubKey is DHPublicKey)
			{
				if (pubKey is BCDHPublicKey)
				{
					return ((BCDHPublicKey)pubKey).engineGetKeyParameters();
				}
				else
				{
					DHPublicKey pub = (DHPublicKey)pubKey;

					DHParameterSpec @params = pub.getParams();

					if (@params is DHDomainParameterSpec)
					{
						return new DHPublicKeyParameters(pub.getY(), ((DHDomainParameterSpec)@params).getDomainParameters());
					}
					return new DHPublicKeyParameters(pub.getY(), new DHParameters(@params.getP(), @params.getG(), null, @params.getL()));
				}
			}
			else
			{
				throw new InvalidKeyException("public key not a DHPublicKey");
			}
		}

		public class DHwithRFC2631KDF : KeyAgreementSpi
		{
			public DHwithRFC2631KDF() : base("DHwithRFC2631KDF", new DHKEKGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA1KDF : KeyAgreementSpi
		{
			public DHwithSHA1KDF() : base("DHwithSHA1CKDF", new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA224KDF : KeyAgreementSpi
		{
			public DHwithSHA224KDF() : base("DHwithSHA224CKDF", new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHwithSHA256KDF : KeyAgreementSpi
		{
			public DHwithSHA256KDF() : base("DHwithSHA256CKDF", new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHwithSHA384KDF : KeyAgreementSpi
		{
			public DHwithSHA384KDF() : base("DHwithSHA384KDF", new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHwithSHA512KDF : KeyAgreementSpi
		{
			public DHwithSHA512KDF() : base("DHwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHwithSHA1CKDF : KeyAgreementSpi
		{
			public DHwithSHA1CKDF() : base("DHwithSHA1CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHwithSHA224CKDF : KeyAgreementSpi
		{
			public DHwithSHA224CKDF() : base("DHwithSHA224CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHwithSHA256CKDF : KeyAgreementSpi
		{
			public DHwithSHA256CKDF() : base("DHwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHwithSHA384CKDF : KeyAgreementSpi
		{
			public DHwithSHA384CKDF() : base("DHwithSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHwithSHA512CKDF : KeyAgreementSpi
		{
			public DHwithSHA512CKDF() : base("DHwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHUwithSHA1KDF : KeyAgreementSpi
		{
			public DHUwithSHA1KDF() : base("DHUwithSHA1KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHUwithSHA224KDF : KeyAgreementSpi
		{
			public DHUwithSHA224KDF() : base("DHUwithSHA224KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHUwithSHA256KDF : KeyAgreementSpi
		{
			public DHUwithSHA256KDF() : base("DHUwithSHA256KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHUwithSHA384KDF : KeyAgreementSpi
		{
			public DHUwithSHA384KDF() : base("DHUwithSHA384KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHUwithSHA512KDF : KeyAgreementSpi
		{
			public DHUwithSHA512KDF() : base("DHUwithSHA512KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class DHUwithSHA1CKDF : KeyAgreementSpi
		{
			public DHUwithSHA1CKDF() : base("DHUwithSHA1CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class DHUwithSHA224CKDF : KeyAgreementSpi
		{
			public DHUwithSHA224CKDF() : base("DHUwithSHA224CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class DHUwithSHA256CKDF : KeyAgreementSpi
		{
			public DHUwithSHA256CKDF() : base("DHUwithSHA256CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class DHUwithSHA384CKDF : KeyAgreementSpi
		{
			public DHUwithSHA384CKDF() : base("DHUwithSHA384CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class DHUwithSHA512CKDF : KeyAgreementSpi
		{
			public DHUwithSHA512CKDF() : base("DHUwithSHA512CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class MQVwithSHA1KDF : KeyAgreementSpi
		{
			public MQVwithSHA1KDF() : base("MQVwithSHA1KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class MQVwithSHA224KDF : KeyAgreementSpi
		{
			public MQVwithSHA224KDF() : base("MQVwithSHA224KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class MQVwithSHA256KDF : KeyAgreementSpi
		{
			public MQVwithSHA256KDF() : base("MQVwithSHA256KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class MQVwithSHA384KDF : KeyAgreementSpi
		{
			public MQVwithSHA384KDF() : base("MQVwithSHA384KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class MQVwithSHA512KDF : KeyAgreementSpi
		{
			public MQVwithSHA512KDF() : base("MQVwithSHA512KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()))
			{
			}
		}

		public class MQVwithSHA1CKDF : KeyAgreementSpi
		{
			public MQVwithSHA1CKDF() : base("MQVwithSHA1CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()))
			{
			}
		}

		public class MQVwithSHA224CKDF : KeyAgreementSpi
		{
			public MQVwithSHA224CKDF() : base("MQVwithSHA224CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()))
			{
			}
		}

		public class MQVwithSHA256CKDF : KeyAgreementSpi
		{
			public MQVwithSHA256CKDF() : base("MQVwithSHA256CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()))
			{
			}
		}

		public class MQVwithSHA384CKDF : KeyAgreementSpi
		{
			public MQVwithSHA384CKDF() : base("MQVwithSHA384CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()))
			{
			}
		}

		public class MQVwithSHA512CKDF : KeyAgreementSpi
		{
			public MQVwithSHA512CKDF() : base("MQVwithSHA512CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()))
			{
			}
		}
	}

}