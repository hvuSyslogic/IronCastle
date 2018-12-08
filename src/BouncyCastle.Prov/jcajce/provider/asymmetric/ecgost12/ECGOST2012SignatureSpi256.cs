using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ecgost12
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using GOST3411_2012_256Digest = org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECKeyParameters = org.bouncycastle.crypto.@params.ECKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ECGOST3410_2012Signer = org.bouncycastle.crypto.signers.ECGOST3410_2012Signer;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using ECKey = org.bouncycastle.jce.interfaces.ECKey;
	using ECPublicKey = org.bouncycastle.jce.interfaces.ECPublicKey;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;

	/// <summary>
	/// Signature for GOST34.10 2012 256. Algorithm is the same as for GOST34.10 2001
	/// </summary>
	public class ECGOST2012SignatureSpi256 : java.security.SignatureSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		private bool InstanceFieldsInitialized = false;

		private void InitializeInstanceFields()
		{
			halfSize = size / 2;
		}

		private Digest digest;
		private DSAExt signer;
		private int size = 64;
		private int halfSize;

		public ECGOST2012SignatureSpi256()
		{
			if (!InstanceFieldsInitialized)
			{
				InitializeInstanceFields();
				InstanceFieldsInitialized = true;
			}
			this.digest = new GOST3411_2012_256Digest();
			this.signer = new ECGOST3410_2012Signer();
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			ECKeyParameters param;

			if (publicKey is ECPublicKey)
			{
				param = (ECKeyParameters)generatePublicKeyParameter(publicKey);
			}
			else
			{
				try
				{
					byte[] bytes = publicKey.getEncoded();

					publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

					param = (ECKeyParameters)ECUtil.generatePublicKeyParameter(publicKey);
				}
				catch (Exception)
				{
					throw new InvalidKeyException("cannot recognise key type in ECGOST-2012-256 signer");
				}
			}

			if (param.getParameters().getN().bitLength() > 256)
			{
				throw new InvalidKeyException("key out of range for ECGOST-2012-256");
			}

			digest.reset();
			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			ECKeyParameters param;

			if (privateKey is ECKey)
			{
				param = (ECKeyParameters)ECUtil.generatePrivateKeyParameter(privateKey);
			}
			else
			{
				throw new InvalidKeyException("cannot recognise key type in ECGOST-2012-256 signer");
			}

			if (param.getParameters().getN().bitLength() > 256)
			{
				throw new InvalidKeyException("key out of range for ECGOST-2012-256");
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
				byte[] sigBytes = new byte[size];
				BigInteger[] sig = signer.generateSignature(hash);
				byte[] r = sig[0].toByteArray();
				byte[] s = sig[1].toByteArray();

				if (s[0] != 0)
				{
					JavaSystem.arraycopy(s, 0, sigBytes, halfSize - s.Length, s.Length);
				}
				else
				{
					JavaSystem.arraycopy(s, 1, sigBytes, halfSize - (s.Length - 1), s.Length - 1);
				}

				if (r[0] != 0)
				{
					JavaSystem.arraycopy(r, 0, sigBytes, size - r.Length, r.Length);
				}
				else
				{
					JavaSystem.arraycopy(r, 1, sigBytes, size - (r.Length - 1), r.Length - 1);
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
				byte[] r = new byte[halfSize];
				byte[] s = new byte[halfSize];

				JavaSystem.arraycopy(sigBytes, 0, s, 0, halfSize);

				JavaSystem.arraycopy(sigBytes, halfSize, r, 0, halfSize);

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

		/// @deprecated replaced with "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)" 
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
			return (key is BCECGOST3410_2012PublicKey) ? ((BCECGOST3410_2012PublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
		}
	}

}