using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec.rfc7748;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.@params
{

			
	public sealed class X25519PrivateKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = X25519.SCALAR_SIZE;
		public const int SECRET_SIZE = X25519.POINT_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public X25519PrivateKeyParameters(SecureRandom random) : base(true)
		{

			X25519.generatePrivateKey(random, data);
		}

		public X25519PrivateKeyParameters(byte[] buf, int off) : base(true)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public X25519PrivateKeyParameters(InputStream input) : base(true)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of X25519 private key");
			}
		}

		public void encode(byte[] buf, int off)
		{
			JavaSystem.arraycopy(data, 0, buf, off, KEY_SIZE);
		}

		public byte[] getEncoded()
		{
			return Arrays.clone(data);
		}

		public X25519PublicKeyParameters generatePublicKey()
		{
			byte[] publicKey = new byte[X25519.POINT_SIZE];
			X25519.generatePublicKey(data, 0, publicKey, 0);
			return new X25519PublicKeyParameters(publicKey, 0);
		}

		public void generateSecret(X25519PublicKeyParameters publicKey, byte[] buf, int off)
		{
			byte[] encoded = new byte[X25519.POINT_SIZE];
			publicKey.encode(encoded, 0);
			if (!X25519.calculateAgreement(data, 0, encoded, 0, buf, off))
			{
				throw new IllegalStateException("X25519 agreement failed");
			}
		}
	}

}