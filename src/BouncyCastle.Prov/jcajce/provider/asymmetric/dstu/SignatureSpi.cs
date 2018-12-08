using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using DSTU4145Params = org.bouncycastle.asn1.ua.DSTU4145Params;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using GOST3411Digest = org.bouncycastle.crypto.digests.GOST3411Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DSTU4145Signer = org.bouncycastle.crypto.signers.DSTU4145Signer;
	using ECUtil = org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
	using ECKey = org.bouncycastle.jce.interfaces.ECKey;

	public class SignatureSpi : java.security.SignatureSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		private Digest digest;
		private DSAExt signer;

		public SignatureSpi()
		{
			this.signer = new DSTU4145Signer();
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param;

			if (publicKey is BCDSTU4145PublicKey)
			{
				param = ((BCDSTU4145PublicKey)publicKey).engineGetKeyParameters();
				digest = new GOST3411Digest(expandSbox(((BCDSTU4145PublicKey)publicKey).getSbox()));
			}
			else
			{
				param = ECUtil.generatePublicKeyParameter(publicKey);
				digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
			}

			signer.init(false, param);
		}

		public virtual byte[] expandSbox(byte[] compressed)
		{
			byte[] expanded = new byte[128];

			for (int i = 0; i < compressed.Length; i++)
			{
				expanded[i * 2] = (byte)((compressed[i] >> 4) & 0xf);
				expanded[i * 2 + 1] = (byte)(compressed[i] & 0xf);
			}
			return expanded;
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param = null;

			if (privateKey is BCDSTU4145PrivateKey)
			{
				// TODO: add parameters support.
				param = ECUtil.generatePrivateKeyParameter(privateKey);
				digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
			}
			else if (privateKey is ECKey)
			{
				param = ECUtil.generatePrivateKeyParameter(privateKey);
				digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
			}

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
				BigInteger[] sig = signer.generateSignature(hash);
				byte[] r = sig[0].toByteArray();
				byte[] s = sig[1].toByteArray();

				byte[] sigBytes = new byte[(r.Length > s.Length ? r.Length * 2 : s.Length * 2)];
				JavaSystem.arraycopy(s, 0, sigBytes, (sigBytes.Length / 2) - s.Length, s.Length);
				JavaSystem.arraycopy(r, 0, sigBytes, sigBytes.Length - r.Length, r.Length);

				return (new DEROctetString(sigBytes)).getEncoded();
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
				byte[] bytes = ((ASN1OctetString)ASN1OctetString.fromByteArray(sigBytes)).getOctets();

				byte[] r = new byte[bytes.Length / 2];
				byte[] s = new byte[bytes.Length / 2];

				JavaSystem.arraycopy(bytes, 0, s, 0, bytes.Length / 2);

				JavaSystem.arraycopy(bytes, bytes.Length / 2, r, 0, bytes.Length / 2);

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
	}

}