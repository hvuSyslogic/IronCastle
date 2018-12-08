using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	using Ed25519 = org.bouncycastle.math.ec.rfc8032.Ed25519;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public sealed class Ed25519PrivateKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = Ed25519.SECRET_KEY_SIZE;
		public static readonly int SIGNATURE_SIZE = Ed25519.SIGNATURE_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public Ed25519PrivateKeyParameters(SecureRandom random) : base(true)
		{

			Ed25519.generatePrivateKey(random, data);
		}

		public Ed25519PrivateKeyParameters(byte[] buf, int off) : base(true)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public Ed25519PrivateKeyParameters(InputStream input) : base(true)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of Ed25519 private key");
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

		public Ed25519PublicKeyParameters generatePublicKey()
		{
			byte[] publicKey = new byte[Ed25519.PUBLIC_KEY_SIZE];
			Ed25519.generatePublicKey(data, 0, publicKey, 0);
			return new Ed25519PublicKeyParameters(publicKey, 0);
		}

		public void sign(int algorithm, Ed25519PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
		{
			byte[] pk = new byte[Ed25519.PUBLIC_KEY_SIZE];
			if (null == publicKey)
			{
				Ed25519.generatePublicKey(data, 0, pk, 0);
			}
			else
			{
				publicKey.encode(pk, 0);
			}

			switch (algorithm)
			{
			case Ed25519.Algorithm.Ed25519:
			{
				if (null != ctx)
				{
					throw new IllegalArgumentException("ctx");
				}

				Ed25519.sign(data, 0, pk, 0, msg, msgOff, msgLen, sig, sigOff);
				break;
			}
			case Ed25519.Algorithm.Ed25519ctx:
			{
				Ed25519.sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
				break;
			}
			case Ed25519.Algorithm.Ed25519ph:
			{
				if (Ed25519.PREHASH_SIZE != msgLen)
				{
					throw new IllegalArgumentException("msgLen");
				}

				Ed25519.signPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
				break;
			}
			default:
			{
				throw new IllegalArgumentException("algorithm");
			}
			}
		}
	}

}