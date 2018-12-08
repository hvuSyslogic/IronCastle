using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using GOST3411Digest = org.bouncycastle.crypto.digests.GOST3411Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECGOST3410Signer = org.bouncycastle.crypto.signers.ECGOST3410Signer;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using GOST3410Util = org.bouncycastle.jcajce.provider.asymmetric.util.GOST3410Util;
	using ECKey = org.bouncycastle.jce.interfaces.ECKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using GOST3410Key = org.bouncycastle.jce.interfaces.GOST3410Key;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	public class SignatureSpi : java.security.SignatureSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		private Digest digest;
		private DSAExt signer;

		public SignatureSpi()
		{
			this.digest = new GOST3411Digest();
			this.signer = new ECGOST3410Signer();
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param;

			if (publicKey is ECPublicKey)
			{
				param = generatePublicKeyParameter(publicKey);
			}
			else if (publicKey is GOST3410Key)
			{
				param = GOST3410Util.generatePublicKeyParameter(publicKey);
			}
			else
			{
				try
				{
					byte[] bytes = publicKey.getEncoded();

					publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

					param = ECUtil.generatePublicKeyParameter(publicKey);
				}
				catch (Exception)
				{
					throw new InvalidKeyException("can't recognise key type in DSA based signer");
				}
			}

			digest.reset();
			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param;

			if (privateKey is ECKey)
			{
				param = ECUtil.generatePrivateKeyParameter(privateKey);
			}
			else
			{
				param = GOST3410Util.generatePrivateKeyParameter(privateKey);
			}

			digest.reset();

			if (appRandom != null)
			{
				signer.init(true, new ParametersWithRandom(param, appRandom));
			}
			else
			{
				signer.init(true, param);
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
			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			try
			{
				byte[] sigBytes = new byte[64];
				BigInteger[] sig = signer.generateSignature(hash);
				byte[] r = sig[0].toByteArray();
				byte[] s = sig[1].toByteArray();

				if (s[0] != 0)
				{
					JavaSystem.arraycopy(s, 0, sigBytes, 32 - s.Length, s.Length);
				}
				else
				{
					JavaSystem.arraycopy(s, 1, sigBytes, 32 - (s.Length - 1), s.Length - 1);
				}

				if (r[0] != 0)
				{
					JavaSystem.arraycopy(r, 0, sigBytes, 64 - r.Length, r.Length);
				}
				else
				{
					JavaSystem.arraycopy(r, 1, sigBytes, 64 - (r.Length - 1), r.Length - 1);
				}

				return sigBytes;
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			BigInteger[] sig;

			try
			{
				byte[] r = new byte[32];
				byte[] s = new byte[32];

				JavaSystem.arraycopy(sigBytes, 0, s, 0, 32);

				JavaSystem.arraycopy(sigBytes, 32, r, 0, 32);

				sig = new BigInteger[2];
				sig[0] = new BigInteger(1, r);
				sig[1] = new BigInteger(1, s);
			}
			catch (Exception)
			{
				throw new SignatureException("error decoding signature bytes.");
			}

			return signer.verifySignature(hash, sig[0], sig[1]);
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

		internal static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey key)
		{
			return (key is BCECGOST3410PublicKey) ? ((BCECGOST3410PublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
		}
	}

}