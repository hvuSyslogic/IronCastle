using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.signers
{
	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using Ed448 = org.bouncycastle.math.ec.rfc8032.Ed448;
	using Arrays = org.bouncycastle.util.Arrays;

	public class Ed448phSigner : Signer
	{
		private readonly Xof prehash = Ed448.createPrehash();
		private readonly byte[] context;

		private bool forSigning;
		private Ed448PrivateKeyParameters privateKey;
		private Ed448PublicKeyParameters publicKey;

		public Ed448phSigner(byte[] context)
		{
			this.context = Arrays.clone(context);
		}

		public virtual void init(bool forSigning, CipherParameters parameters)
		{
			this.forSigning = forSigning;

			if (forSigning)
			{
				// TODO Allow AsymmetricCipherKeyPair to be a CipherParameters?

				this.privateKey = (Ed448PrivateKeyParameters)parameters;
				this.publicKey = privateKey.generatePublicKey();
			}
			else
			{
				this.privateKey = null;
				this.publicKey = (Ed448PublicKeyParameters)parameters;
			}

			reset();
		}

		public virtual void update(byte b)
		{
			prehash.update(b);
		}

		public virtual void update(byte[] buf, int off, int len)
		{
			prehash.update(buf, off, len);
		}

		public virtual byte[] generateSignature()
		{
			if (!forSigning || null == privateKey)
			{
				throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
			}

			byte[] msg = new byte[Ed448.PREHASH_SIZE];
			if (Ed448.PREHASH_SIZE != prehash.doFinal(msg, 0, Ed448.PREHASH_SIZE))
			{
				throw new IllegalStateException("Prehash digest failed");
			}

			byte[] signature = new byte[Ed448PrivateKeyParameters.SIGNATURE_SIZE];
			privateKey.sign(Ed448.Algorithm.Ed448ph, publicKey, context, msg, 0, Ed448.PREHASH_SIZE, signature, 0);
			return signature;
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning || null == publicKey)
			{
				throw new IllegalStateException("Ed448phSigner not initialised for verification");
			}

			byte[] pk = publicKey.getEncoded();
			return Ed448.verifyPrehash(signature, 0, pk, 0, context, prehash);
		}

		public virtual void reset()
		{
			prehash.reset();
		}
	}

}