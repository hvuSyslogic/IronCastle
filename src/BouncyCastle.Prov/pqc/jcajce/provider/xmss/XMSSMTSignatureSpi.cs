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
	using XMSSMTPrivateKeyParameters = org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
	using XMSSMTSigner = org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner;
	using StateAwareSignature = org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;

	public class XMSSMTSignatureSpi : Signature, StateAwareSignature
	{
		public XMSSMTSignatureSpi(string algorithm) : base(algorithm)
		{
		}

		private Digest digest;
		private XMSSMTSigner signer;
		private ASN1ObjectIdentifier treeDigest;
		private SecureRandom random;

		public XMSSMTSignatureSpi(string sigName, Digest digest, XMSSMTSigner signer) : base(sigName)
		{

			this.digest = digest;
			this.signer = signer;
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (publicKey is BCXMSSMTPublicKey)
			{
				CipherParameters param = ((BCXMSSMTPublicKey)publicKey).getKeyParams();

				treeDigest = null;
				digest.reset();
				signer.init(false, param);
			}
			else
			{
				throw new InvalidKeyException("unknown public key passed to XMSSMT");
			}
		}

		public virtual void engineInitSign(PrivateKey privateKey, SecureRandom random)
		{
			this.random = random;
			engineInitSign(privateKey);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (privateKey is BCXMSSMTPrivateKey)
			{
				CipherParameters param = ((BCXMSSMTPrivateKey)privateKey).getKeyParams();

				treeDigest = ((BCXMSSMTPrivateKey)privateKey).getTreeDigestOID();
				if (random != null)
				{
					param = new ParametersWithRandom(param, random);
				}

				digest.reset();
				signer.init(true, param);
			}
			else
			{
				throw new InvalidKeyException("unknown private key passed to XMSSMT");
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
			PrivateKey rKey = new BCXMSSMTPrivateKey(treeDigest, (XMSSMTPrivateKeyParameters)signer.getUpdatedPrivateKey());

			treeDigest = null;

			return rKey;
		}

		public class withSha256 : XMSSMTSignatureSpi
		{
			public withSha256() : base("XMSSMT-SHA256", new NullDigest(), new XMSSMTSigner())
			{
			}
		}

		public class withShake128 : XMSSMTSignatureSpi
		{
			public withShake128() : base("XMSSMT-SHAKE128", new NullDigest(), new XMSSMTSigner())
			{
			}
		}

		public class withSha512 : XMSSMTSignatureSpi
		{
			public withSha512() : base("XMSSMT-SHA512", new NullDigest(), new XMSSMTSigner())
			{
			}
		}

		public class withShake256 : XMSSMTSignatureSpi
		{
			public withShake256() : base("XMSSMT-SHAKE256", new NullDigest(), new XMSSMTSigner())
			{
			}
		}

		public class withSha256andPrehash : XMSSMTSignatureSpi
		{
			public withSha256andPrehash() : base("SHA256withXMSSMT-SHA256", new SHA256Digest(), new XMSSMTSigner())
			{
			}
		}

		public class withShake128andPrehash : XMSSMTSignatureSpi
		{
			public withShake128andPrehash() : base("SHAKE128withXMSSMT-SHAKE128", new SHAKEDigest(128), new XMSSMTSigner())
			{
			}
		}

		public class withSha512andPrehash : XMSSMTSignatureSpi
		{
			public withSha512andPrehash() : base("SHA512withXMSSMT-SHA512", new SHA512Digest(), new XMSSMTSigner())
			{
			}
		}

		public class withShake256andPrehash : XMSSMTSignatureSpi
		{
			public withShake256andPrehash() : base("SHAKE256withXMSSMT-SHAKE256", new SHAKEDigest(256), new XMSSMTSigner())
			{
			}
		}
	}

}