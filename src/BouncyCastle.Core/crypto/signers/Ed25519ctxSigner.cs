using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.signers
{

	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using Ed25519 = org.bouncycastle.math.ec.rfc8032.Ed25519;
	using Arrays = org.bouncycastle.util.Arrays;

	public class Ed25519ctxSigner : Signer
	{
		private readonly Buffer buffer = new Buffer();
		private readonly byte[] context;

		private bool forSigning;
		private Ed25519PrivateKeyParameters privateKey;
		private Ed25519PublicKeyParameters publicKey;

		public Ed25519ctxSigner(byte[] context)
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
			buffer.write(b);
		}

		public virtual void update(byte[] buf, int off, int len)
		{
			buffer.write(buf, off, len);
		}

		public virtual byte[] generateSignature()
		{
			if (!forSigning || null == privateKey)
			{
				throw new IllegalStateException("Ed25519ctxSigner not initialised for signature generation.");
			}

			return buffer.generateSignature(privateKey, publicKey, context);
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning || null == publicKey)
			{
				throw new IllegalStateException("Ed25519ctxSigner not initialised for verification");
			}

			return buffer.verifySignature(publicKey, context, signature);
		}

		public virtual void reset()
		{
			buffer.reset();
		}

		public class Buffer : ByteArrayOutputStream
		{
			public virtual byte[] generateSignature(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey, byte[] ctx)
			{
				lock (this)
				{
					byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
					privateKey.sign(Ed25519.Algorithm.Ed25519ctx, publicKey, ctx, buf, 0, count, signature, 0);
					reset();
					return signature;
				}
			}

			public virtual bool verifySignature(Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
			{
				lock (this)
				{
					byte[] pk = publicKey.getEncoded();
					bool result = Ed25519.verify(signature, 0, pk, 0, ctx, buf, 0, count);
					reset();
					return result;
				}
			}

			public virtual void reset()
			{
				lock (this)
				{
					Arrays.fill(buf, 0, count, (byte)0);
					this.count = 0;
				}
			}
		}
	}

}