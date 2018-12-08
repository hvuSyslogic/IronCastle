using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using DSAExt = org.bouncycastle.crypto.DSAExt;
	using Digest = org.bouncycastle.crypto.Digest;
	using DSAEncoding = org.bouncycastle.crypto.signers.DSAEncoding;

	public abstract class DSABase : SignatureSpi, PKCSObjectIdentifiers, X509ObjectIdentifiers
	{
		protected internal Digest digest;
		protected internal DSAExt signer;
		protected internal DSAEncoding encoding;

		public DSABase(Digest digest, DSAExt signer, DSAEncoding encoding)
		{
			this.digest = digest;
			this.signer = signer;
			this.encoding = encoding;
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

				return encoding.encode(signer.getOrder(), sig[0], sig[1]);
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
				sig = encoding.decode(signer.getOrder(), sigBytes);
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
	}

}