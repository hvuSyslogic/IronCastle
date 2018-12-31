using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.signers
{

		
	public class DSADigestSigner : Signer
	{
		private readonly DSA dsa;
		private readonly Digest digest;
		private readonly DSAEncoding encoding;
		private bool forSigning;

		public DSADigestSigner(DSA dsa, Digest digest)
		{
			this.dsa = dsa;
			this.digest = digest;
			this.encoding = StandardDSAEncoding.INSTANCE;
		}

		public DSADigestSigner(DSAExt dsa, Digest digest, DSAEncoding encoding)
		{
			this.dsa = dsa;
			this.digest = digest;
			this.encoding = encoding;
		}

		public virtual void init(bool forSigning, CipherParameters parameters)
		{
			this.forSigning = forSigning;

			AsymmetricKeyParameter k;

			if (parameters is ParametersWithRandom)
			{
				k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).getParameters();
			}
			else
			{
				k = (AsymmetricKeyParameter)parameters;
			}

			if (forSigning && !k.isPrivate())
			{
				throw new IllegalArgumentException("Signing Requires Private Key.");
			}

			if (!forSigning && k.isPrivate())
			{
				throw new IllegalArgumentException("Verification Requires Public Key.");
			}

			reset();

			dsa.init(forSigning, parameters);
		}

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		public virtual void update(byte input)
		{
			digest.update(input);
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] input, int inOff, int length)
		{
			digest.update(input, inOff, length);
		}

		/// <summary>
		/// Generate a signature for the message we've been loaded with using
		/// the key we were initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			if (!forSigning)
			{
				throw new IllegalStateException("DSADigestSigner not initialised for signature generation.");
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			BigInteger[] sig = dsa.generateSignature(hash);

			try
			{
				return encoding.encode(getOrder(), sig[0], sig[1]);
			}
			catch (Exception)
			{
				throw new IllegalStateException("unable to encode signature");
			}
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning)
			{
				throw new IllegalStateException("DSADigestSigner not initialised for verification");
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			try
			{
				BigInteger[] sig = encoding.decode(getOrder(), signature);

				return dsa.verifySignature(hash, sig[0], sig[1]);
			}
			catch (Exception)
			{
				return false;
			}
		}

		public virtual void reset()
		{
			digest.reset();
		}

		public virtual BigInteger getOrder()
		{
			return dsa is DSAExt ? ((DSAExt)dsa).getOrder() : null;
		}
	}

}