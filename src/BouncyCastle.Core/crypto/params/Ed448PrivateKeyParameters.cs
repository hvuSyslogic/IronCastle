using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec.rfc8032;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.@params
{

			
	public sealed class Ed448PrivateKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = Ed448.SECRET_KEY_SIZE;
		public static readonly int SIGNATURE_SIZE = Ed448.SIGNATURE_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public Ed448PrivateKeyParameters(SecureRandom random) : base(true)
		{

			Ed448.generatePrivateKey(random, data);
		}

		public Ed448PrivateKeyParameters(byte[] buf, int off) : base(true)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public Ed448PrivateKeyParameters(InputStream input) : base(true)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of Ed448 private key");
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

		public Ed448PublicKeyParameters generatePublicKey()
		{
			byte[] publicKey = new byte[Ed448.PUBLIC_KEY_SIZE];
			Ed448.generatePublicKey(data, 0, publicKey, 0);
			return new Ed448PublicKeyParameters(publicKey, 0);
		}

		public void sign(int algorithm, Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
		{
			byte[] pk = new byte[Ed448.PUBLIC_KEY_SIZE];
			if (null == publicKey)
			{
				Ed448.generatePublicKey(data, 0, pk, 0);
			}
			else
			{
				publicKey.encode(pk, 0);
			}

			switch (algorithm)
			{
			case Ed448.Algorithm.Ed448:
			{
				Ed448.sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
				break;
			}
			case Ed448.Algorithm.Ed448ph:
			{
				if (Ed448.PREHASH_SIZE != msgLen)
				{
					throw new IllegalArgumentException("msgLen");
				}

				Ed448.signPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
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