using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using OpenSSHPrivateKeyUtil = org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
	using OpenSSHPublicKeyUtil = org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using OpenSSHPrivateKeySpec = org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec;
	using OpenSSHPublicKeySpec = org.bouncycastle.jce.spec.OpenSSHPublicKeySpec;

	public class KeyFactorySpi : BaseKeyFactorySpi
	{
		public KeyFactorySpi()
		{
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(DSAPublicKeySpec)) && key is DSAPublicKey)
			{
				DSAPublicKey k = (DSAPublicKey)key;

				return new DSAPublicKeySpec(k.getY(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
			}
			else if (spec.isAssignableFrom(typeof(DSAPrivateKeySpec)) && key is DSAPrivateKey)
			{
				DSAPrivateKey k = (DSAPrivateKey)key;

				return new DSAPrivateKeySpec(k.getX(), k.getParams().getP(), k.getParams().getQ(), k.getParams().getG());
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPublicKeySpec)) && key is DSAPublicKey)
			{
				DSAPublicKey k = (DSAPublicKey)key;
				try
				{
					return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new DSAPublicKeyParameters(k.getY(), new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()))));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to produce encoding: " + e.Message);
				}
			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPrivateKeySpec)) && key is DSAPrivateKey)
			{
				DSAPrivateKey k = (DSAPrivateKey)key;
				try
				{
					return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new DSAPrivateKeyParameters(k.getX(), new DSAParameters(k.getParams().getP(), k.getParams().getQ(), k.getParams().getG()))));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to produce encoding: " + e.Message);
				}
			}

			return base.engineGetKeySpec(key, spec);
		}

		public virtual Key engineTranslateKey(Key key)
		{
			if (key is DSAPublicKey)
			{
				return new BCDSAPublicKey((DSAPublicKey)key);
			}
			else if (key is DSAPrivateKey)
			{
				return new BCDSAPrivateKey((DSAPrivateKey)key);
			}

			throw new InvalidKeyException("key type unknown");
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (DSAUtil.isDsaOid(algOid))
			{
				return new BCDSAPrivateKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (DSAUtil.isDsaOid(algOid))
			{
				return new BCDSAPublicKey(keyInfo);
			}
			else
			{
				throw new IOException("algorithm identifier " + algOid + " in key not recognised");
			}
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is DSAPrivateKeySpec)
			{
				return new BCDSAPrivateKey((DSAPrivateKeySpec)keySpec);
			}
			else if (keySpec is OpenSSHPrivateKeySpec)
			{
				CipherParameters @params = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
				if (@params is DSAPrivateKeyParameters)
				{
					return engineGeneratePrivate(new DSAPrivateKeySpec(((DSAPrivateKeyParameters)@params).getX(), ((DSAPrivateKeyParameters)@params).getParameters().getP(), ((DSAPrivateKeyParameters)@params).getParameters().getQ(), ((DSAPrivateKeyParameters)@params).getParameters().getG()));
				}
				else
				{
					throw new IllegalArgumentException("openssh private key is not dsa privare key");
				}

			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is DSAPublicKeySpec)
			{
				try
				{
					return new BCDSAPublicKey((DSAPublicKeySpec)keySpec);
				}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final Exception e)
				catch (Exception e)
				{
					throw new InvalidKeySpecExceptionAnonymousInnerClass(this, "invalid KeySpec: " + e.getMessage(), e);
				}
			}
			else if (keySpec is OpenSSHPublicKeySpec)
			{
				CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());

				if (parameters is DSAPublicKeyParameters)
				{
					return engineGeneratePublic(new DSAPublicKeySpec(((DSAPublicKeyParameters)parameters).getY(), ((DSAPublicKeyParameters)parameters).getParameters().getP(), ((DSAPublicKeyParameters)parameters).getParameters().getQ(), ((DSAPublicKeyParameters)parameters).getParameters().getG()));
				}

				throw new IllegalArgumentException("openssh public key is not dsa public key");

			}

			return base.engineGeneratePublic(keySpec);
		}

		public class InvalidKeySpecExceptionAnonymousInnerClass : InvalidKeySpecException
		{
			private readonly KeyFactorySpi outerInstance;

			private ception e;

			public InvalidKeySpecExceptionAnonymousInnerClass(KeyFactorySpi outerInstance, string getMessage, ception e) : base(getMessage)
			{
				this.outerInstance = outerInstance;
				this.e = e;
			}

			public Exception getCause()
			{
				return e;
			}
		}
	}

}