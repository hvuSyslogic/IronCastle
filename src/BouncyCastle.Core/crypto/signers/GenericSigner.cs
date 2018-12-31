using System;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{
			
	public class GenericSigner : Signer
	{
		private readonly AsymmetricBlockCipher engine;
		private readonly Digest digest;
		private bool forSigning;

		public GenericSigner(AsymmetricBlockCipher engine, Digest digest)
		{
			this.engine = engine;
			this.digest = digest;
		}

		/// <summary>
		/// initialise the signer for signing or verification.
		/// </summary>
		/// <param name="forSigning">
		///            true if for signing, false otherwise </param>
		/// <param name="parameters">
		///            necessary parameters. </param>
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
				throw new IllegalArgumentException("signing requires private key");
			}

			if (!forSigning && k.isPrivate())
			{
				throw new IllegalArgumentException("verification requires public key");
			}

			reset();

			engine.init(forSigning, parameters);
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
		/// Generate a signature for the message we've been loaded with using the key
		/// we were initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			if (!forSigning)
			{
				throw new IllegalStateException("GenericSigner not initialised for signature generation.");
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			return engine.processBlock(hash, 0, hash.Length);
		}

		/// <summary>
		/// return true if the internal state represents the signature described in
		/// the passed in array.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning)
			{
				throw new IllegalStateException("GenericSigner not initialised for verification");
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			try
			{
				byte[] sig = engine.processBlock(signature, 0, signature.Length);

				// Extend with leading zeroes to match the digest size, if necessary.
				if (sig.Length < hash.Length)
				{
					byte[] tmp = new byte[hash.Length];
					JavaSystem.arraycopy(sig, 0, tmp, tmp.Length - sig.Length, sig.Length);
					sig = tmp;
				}

				return Arrays.constantTimeAreEqual(sig, hash);
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
	}

}