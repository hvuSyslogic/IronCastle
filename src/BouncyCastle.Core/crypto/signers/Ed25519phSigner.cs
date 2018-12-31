using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec.rfc8032;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{
				
	public class Ed25519phSigner : Signer
	{
		private readonly Digest prehash = Ed25519.createPrehash();
		private readonly byte[] context;

		private bool forSigning;
		private Ed25519PrivateKeyParameters privateKey;
		private Ed25519PublicKeyParameters publicKey;

		public Ed25519phSigner(byte[] context)
		{
			this.context = Arrays.clone(context);
		}

		public virtual void init(bool forSigning, CipherParameters parameters)
		{
			this.forSigning = forSigning;

			if (forSigning)
			{
				// TODO Allow AsymmetricCipherKeyPair to be a CipherParameters?

				this.privateKey = (Ed25519PrivateKeyParameters)parameters;
				this.publicKey = privateKey.generatePublicKey();
			}
			else
			{
				this.privateKey = null;
				this.publicKey = (Ed25519PublicKeyParameters)parameters;
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
				throw new IllegalStateException("Ed25519phSigner not initialised for signature generation.");
			}

			byte[] msg = new byte[Ed25519.PREHASH_SIZE];
			if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
			{
				throw new IllegalStateException("Prehash digest failed");
			}

			byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
			privateKey.sign(Ed25519.Algorithm.Ed25519ph, publicKey, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
			return signature;
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning || null == publicKey)
			{
				throw new IllegalStateException("Ed25519phSigner not initialised for verification");
			}

			byte[] pk = publicKey.getEncoded();
			return Ed25519.verifyPrehash(signature, 0, pk, 0, context, prehash);
		}

		public virtual void reset()
		{
			prehash.reset();
		}
	}

}