namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using CryptoException = org.bouncycastle.crypto.CryptoException;
	using Signer = org.bouncycastle.crypto.Signer;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using Ed25519Signer = org.bouncycastle.crypto.signers.Ed25519Signer;
	using Ed448Signer = org.bouncycastle.crypto.signers.Ed448Signer;

	public class SignatureSpi : java.security.SignatureSpi
	{
		private static readonly byte[] EMPTY_CONTEXT = new byte[0];

		private readonly string algorithm;

		private Signer signer;

		public SignatureSpi(string algorithm)
		{
			this.algorithm = algorithm;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (publicKey is BCEdDSAPublicKey)
			{
				AsymmetricKeyParameter pub = ((BCEdDSAPublicKey)publicKey).engineGetKeyParameters();

				if (pub is Ed448PublicKeyParameters)
				{
					signer = getSigner("Ed448");
				}
				else
				{
					signer = getSigner("Ed25519");
				}

				signer.init(false, pub);
			}
			else
			{
				throw new InvalidKeyException("cannot identify EdDSA public key");
			}
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (privateKey is BCEdDSAPrivateKey)
			{
				AsymmetricKeyParameter priv = ((BCEdDSAPrivateKey)privateKey).engineGetKeyParameters();

				if (priv is Ed448PrivateKeyParameters)
				{
					signer = getSigner("Ed448");
				}
				else
				{
					signer = getSigner("Ed25519");
				}

				signer.init(true, priv);
			}
			else
			{
				throw new InvalidKeyException("cannot identify EdDSA public key");
			}
		}

		private Signer getSigner(string alg)
		{
			if (!string.ReferenceEquals(algorithm, null) && !alg.Equals(algorithm))
			{
				throw new InvalidKeyException("inappropriate key for " + algorithm);
			}

			if (alg.Equals("Ed448"))
			{
				return new Ed448Signer(EMPTY_CONTEXT);
			}
			else
			{
				return new Ed25519Signer();
			}
		}

		public virtual void engineUpdate(byte b)
		{
			signer.update(b);
		}

		public virtual void engineUpdate(byte[] bytes, int off, int len)
		{
			signer.update(bytes, off, len);
		}

		public virtual byte[] engineSign()
		{
			try
			{
				return signer.generateSignature();
			}
			catch (CryptoException e)
			{
				throw new SignatureException(e.Message);
			}
		}

		public virtual bool engineVerify(byte[] signature)
		{
			return signer.verifySignature(signature);
		}

		public virtual void engineSetParameter(string s, object o)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public virtual object engineGetParameter(string s)
		{
			throw new UnsupportedOperationException("engineGetParameter unsupported");
		}

		public sealed class EdDSA : SignatureSpi
		{
			public EdDSA() : base(null)
			{
			}
		}

		public sealed class Ed448 : SignatureSpi
		{
			public Ed448() : base("Ed448")
			{
			}
		}

		public sealed class Ed25519 : SignatureSpi
		{
			public Ed25519() : base("Ed25519")
			{
			}
		}
	}

}