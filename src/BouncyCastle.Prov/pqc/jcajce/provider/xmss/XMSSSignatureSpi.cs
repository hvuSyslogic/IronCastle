using System;

namespace org.bouncycastle.pqc.jcajce.provider.xmss
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHAKEDigest = org.bouncycastle.crypto.digests.SHAKEDigest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using XMSSPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
	using XMSSSigner = org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
	using StateAwareSignature = org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;

	public class XMSSSignatureSpi : Signature, StateAwareSignature
	{
		public XMSSSignatureSpi(string algorithm) : base(algorithm)
		{
		}

		private Digest digest;
		private XMSSSigner signer;
		private SecureRandom random;
		private ASN1ObjectIdentifier treeDigest;

		public XMSSSignatureSpi(string sigName, Digest digest, XMSSSigner signer) : base(sigName)
		{

			this.digest = digest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (publicKey is BCXMSSPublicKey)
			{
				CipherParameters param = ((BCXMSSPublicKey)publicKey).getKeyParams();

				treeDigest = null;
				digest.reset();
				signer.init(false, param);
			}
			else
			{
				throw new InvalidKeyException("unknown public key passed to XMSS");
			}
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			this.random = random;
			engineInitSign(privateKey);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (privateKey is BCXMSSPrivateKey)
			{
				CipherParameters param = ((BCXMSSPrivateKey)privateKey).getKeyParams();

				treeDigest = ((BCXMSSPrivateKey)privateKey).getTreeDigestOID();
				if (random != null)
				{
					param = new ParametersWithRandom(param, random);
				}

				digest.reset();
				signer.init(true, param);
			}
			else
			{
				throw new InvalidKeyException("unknown private key passed to XMSS");
			}
		}

		public virtual void engineUpdate(byte b)
		{
			digest.update(b);
		}

		public virtual void engineUpdate(byte[] b, int off, int len)
		{
			digest.update(b, off, len);
		}

		public virtual byte[] engineSign()
		{
			byte[] hash = DigestUtil.getDigestResult(digest);

			try
			{
				byte[] sig = signer.generateSignature(hash);

				return sig;
			}
			catch (Exception e)
			{
				if (e is IllegalStateException)
				{
					throw new SignatureException(e.Message);
				}
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			byte[] hash = DigestUtil.getDigestResult(digest);

			return signer.verifySignature(hash, sigBytes);
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			// TODO
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec) 
		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual object engineGetParameter(string param)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public virtual bool isSigningCapable()
		{
			return treeDigest != null;
		}

		public virtual PrivateKey getUpdatedPrivateKey()
		{
			if (treeDigest == null)
			{
				throw new IllegalStateException("signature object not in a signing state");
			}
			PrivateKey rKey = new BCXMSSPrivateKey(treeDigest, (XMSSPrivateKeyParameters)signer.getUpdatedPrivateKey());

			treeDigest = null;

			return rKey;
		}

		public class withSha256 : XMSSSignatureSpi
		{
			public withSha256() : base("XMSS-SHA256", new NullDigest(), new XMSSSigner())
			{
			}
		}

		public class withShake128 : XMSSSignatureSpi
		{
			public withShake128() : base("XMSS-SHAKE128", new NullDigest(), new XMSSSigner())
			{
			}
		}

		public class withSha512 : XMSSSignatureSpi
		{
			public withSha512() : base("XMSS-SHA512", new NullDigest(), new XMSSSigner())
			{
			}
		}

		public class withShake256 : XMSSSignatureSpi
		{
			public withShake256() : base("XMSS-SHAKE256", new NullDigest(), new XMSSSigner())
			{
			}
		}

		public class withSha256andPrehash : XMSSSignatureSpi
		{
			public withSha256andPrehash() : base("SHA256withXMSS-SHA256", new SHA256Digest(), new XMSSSigner())
			{
			}
		}

		public class withShake128andPrehash : XMSSSignatureSpi
		{
			public withShake128andPrehash() : base("SHAKE128withXMSSMT-SHAKE128", new SHAKEDigest(128), new XMSSSigner())
			{
			}
		}

		public class withSha512andPrehash : XMSSSignatureSpi
		{
			public withSha512andPrehash() : base("SHA512withXMSS-SHA512", new SHA512Digest(), new XMSSSigner())
			{
			}
		}

		public class withShake256andPrehash : XMSSSignatureSpi
		{
			public withShake256andPrehash() : base("SHAKE256withXMSS-SHAKE256", new SHAKEDigest(256), new XMSSSigner())
			{
			}
		}
	}

}