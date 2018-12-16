using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.signers
{

	using Ed448PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed448PrivateKeyParameters;
	using Ed448PublicKeyParameters = org.bouncycastle.crypto.@params.Ed448PublicKeyParameters;
	using Ed448 = org.bouncycastle.math.ec.rfc8032.Ed448;
	using Arrays = org.bouncycastle.util.Arrays;


	public class Ed448Signer : Signer
	{
		private readonly Buffer buffer = new Buffer();
		private readonly byte[] context;

		private bool forSigning;
		private Ed448PrivateKeyParameters privateKey;
		private Ed448PublicKeyParameters publicKey;

		public Ed448Signer(byte[] context)
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
				throw new IllegalStateException("Ed448Signer not initialised for signature generation.");
			}

			return buffer.generateSignature(privateKey, publicKey, context);
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning || null == publicKey)
			{
				throw new IllegalStateException("Ed448Signer not initialised for verification");
			}

			return buffer.verifySignature(publicKey, context, signature);
		}

		public virtual void reset()
		{
			buffer.reset();
		}

		public class Buffer : ByteArrayOutputStream
		{
			public virtual byte[] generateSignature(Ed448PrivateKeyParameters privateKey, Ed448PublicKeyParameters publicKey, byte[] ctx)
			{
				lock (this)
				{
					byte[] signature = new byte[Ed448PrivateKeyParameters.SIGNATURE_SIZE];
					privateKey.sign(Ed448.Algorithm.Ed448, publicKey, ctx, buf, 0, buf.Length, signature, 0);
					reset();
					return signature;
				}
			}

			public virtual bool verifySignature(Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] signature)
			{
				lock (this)
				{
					byte[] pk = publicKey.getEncoded();
					bool result = Ed448.verify(signature, 0, pk, 0, ctx, buf, 0, buf.Length);
					reset();
					return result;
				}
			}

			public virtual void reset()
			{
				lock (this)
				{
					Arrays.fill(buf, 0, count(), (byte)0);
					//PORT: this.count = 0;
				}
			}
		}
	}

}