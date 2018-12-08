using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.@params
{

	using X448 = org.bouncycastle.math.ec.rfc7748.X448;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public sealed class X448PrivateKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = X448.SCALAR_SIZE;
		public const int SECRET_SIZE = X448.POINT_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public X448PrivateKeyParameters(SecureRandom random) : base(true)
		{

			X448.generatePrivateKey(random, data);
		}

		public X448PrivateKeyParameters(byte[] buf, int off) : base(true)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public X448PrivateKeyParameters(InputStream input) : base(true)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of X448 private key");
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

		public X448PublicKeyParameters generatePublicKey()
		{
			byte[] publicKey = new byte[X448.POINT_SIZE];
			X448.generatePublicKey(data, 0, publicKey, 0);
			return new X448PublicKeyParameters(publicKey, 0);
		}

		public void generateSecret(X448PublicKeyParameters publicKey, byte[] buf, int off)
		{
			byte[] encoded = new byte[X448.POINT_SIZE];
			publicKey.encode(encoded, 0);
			if (!X448.calculateAgreement(data, 0, encoded, 0, buf, off))
			{
				throw new IllegalStateException("X448 agreement failed");
			}
		}
	}

}