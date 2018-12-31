using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec.rfc8032;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

				
	public class Ed25519Signer : Signer
	{
		private readonly Buffer buffer = new Buffer();

		private bool forSigning;
		private Ed25519PrivateKeyParameters privateKey;
		private Ed25519PublicKeyParameters publicKey;

		public Ed25519Signer()
		{
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
				throw new IllegalStateException("Ed25519Signer not initialised for signature generation.");
			}

			return buffer.generateSignature(privateKey, publicKey);
		}

		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning || null == publicKey)
			{
				throw new IllegalStateException("Ed25519Signer not initialised for verification");
			}

			return buffer.verifySignature(publicKey, signature);
		}

		public virtual void reset()
		{
			buffer.reset();
		}

		public class Buffer : ByteArrayOutputStream
		{
			public virtual byte[] generateSignature(Ed25519PrivateKeyParameters privateKey, Ed25519PublicKeyParameters publicKey)
			{
				lock (this)
				{
					byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
					privateKey.sign(Ed25519.Algorithm.Ed25519, publicKey, null, buf, 0, buf.Length, signature, 0);
					reset();
					return signature;
				}
			}

			public virtual bool verifySignature(Ed25519PublicKeyParameters publicKey, byte[] signature)
			{
				lock (this)
				{
					byte[] pk = publicKey.getEncoded();
					bool result = Ed25519.verify(signature, 0, pk, 0, buf, 0, buf.Length);
					reset();
					return result;
				}
			}

			public override void reset()
			{
				lock (this)
				{
					Arrays.fill(buf, 0, count(), 0);
					//PORT: this.count = 0;
				}
			}
		}
	}

}