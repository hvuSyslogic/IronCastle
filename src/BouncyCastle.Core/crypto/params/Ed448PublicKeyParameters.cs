using org.bouncycastle.math.ec.rfc8032;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.@params
{

			
	public sealed class Ed448PublicKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = Ed448.PUBLIC_KEY_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public Ed448PublicKeyParameters(byte[] buf, int off) : base(false)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public Ed448PublicKeyParameters(InputStream input) : base(false)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of Ed448 public key");
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