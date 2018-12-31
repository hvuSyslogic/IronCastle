using org.bouncycastle.crypto;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto
{
					

	/// <summary>
	/// Implements the sign and verify functions for a Signature Scheme using a hash function to allow processing of large messages.
	/// </summary>
	public class DigestingMessageSigner : Signer
	{
		private readonly Digest messDigest;
		private readonly MessageSigner messSigner;
		private bool forSigning;

		public DigestingMessageSigner(MessageSigner messSigner, Digest messDigest)
		{
			this.messSigner = messSigner;
			this.messDigest = messDigest;
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{

			this.forSigning = forSigning;
			AsymmetricKeyParameter k;

			if (param is ParametersWithRandom)
			{
				k = (AsymmetricKeyParameter)((ParametersWithRandom)param).getParameters();
			}
			else
			{
				k = (AsymmetricKeyParameter)param;
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

			messSigner.init(forSigning, param);
		}


		/// <summary>
		/// This function signs the message that has been updated, making use of the
		/// private key.
		/// </summary>
		/// <returns> the signature of the message. </returns>
		public virtual byte[] generateSignature()
		{
			if (!forSigning)
			{
				throw new IllegalStateException("DigestingMessageSigner not initialised for signature generation.");
			}

			byte[] hash = new byte[messDigest.getDigestSize()];
			messDigest.doFinal(hash, 0);

			return messSigner.generateSignature(hash);
		}

		public virtual void update(byte b)
		{
			messDigest.update(b);
		}

		public virtual void update(byte[] @in, int off, int len)
		{
			messDigest.update(@in, off, len);
		}

		public virtual void reset()
		{
			messDigest.reset();
		}

		/// <summary>
		/// This function verifies the signature of the message that has been
		/// updated, with the aid of the public key.
		/// </summary>
		/// <param name="signature"> the signature of the message is given as a byte array. </param>
		/// <returns> true if the signature has been verified, false otherwise. </returns>
		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning)
			{
				throw new IllegalStateException("DigestingMessageSigner not initialised for verification");
			}

			byte[] hash = new byte[messDigest.getDigestSize()];
			messDigest.doFinal(hash, 0);

			return messSigner.verifySignature(hash, signature);
		}
	}

}