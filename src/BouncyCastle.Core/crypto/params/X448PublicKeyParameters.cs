using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.@params
{

	using X448 = org.bouncycastle.math.ec.rfc7748.X448;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	public sealed class X448PublicKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = X448.POINT_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public X448PublicKeyParameters(byte[] buf, int off) : base(false)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public X448PublicKeyParameters(InputStream input) : base(false)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of X448 public key");
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
	}

}