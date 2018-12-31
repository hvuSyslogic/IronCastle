using org.bouncycastle.crypto;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{
		
	/// <summary>
	/// Crypto functions for XMSS.
	/// </summary>
	public sealed class KeyedHashFunctions
	{

		private readonly Digest digest;
		private readonly int digestSize;

		public KeyedHashFunctions(Digest digest, int digestSize) : base()
		{
			if (digest == null)
			{
				throw new NullPointerException("digest == null");
			}
			this.digest = digest;
			this.digestSize = digestSize;
		}

		private byte[] coreDigest(int fixedValue, byte[] key, byte[] index)
		{
			byte[] @in = XMSSUtil.toBytesBigEndian(fixedValue, digestSize);
			/* fill first n byte of out buffer */
			digest.update(@in, 0, @in.Length);
			/* add key */
			digest.update(key, 0, key.Length);
			/* add index */
			digest.update(index, 0, index.Length);

			byte[] @out = new byte[digestSize];
			if (digest is Xof)
			{
				((Xof)digest).doFinal(@out, 0, digestSize);
			}
			else
			{
				digest.doFinal(@out, 0);
			}
			return @out;
		}

		public byte[] F(byte[] key, byte[] @in)
		{
			if (key.Length != digestSize)
			{
				throw new IllegalArgumentException("wrong key length");
			}
			if (@in.Length != digestSize)
			{
				throw new IllegalArgumentException("wrong in length");
			}
			return coreDigest(0, key, @in);
		}

		public byte[] H(byte[] key, byte[] @in)
		{
			if (key.Length != digestSize)
			{
				throw new IllegalArgumentException("wrong key length");
			}
			if (@in.Length != (2 * digestSize))
			{
				throw new IllegalArgumentException("wrong in length");
			}
			return coreDigest(1, key, @in);
		}

		public byte[] HMsg(byte[] key, byte[] @in)
		{
			if (key.Length != (3 * digestSize))
			{
				throw new IllegalArgumentException("wrong key length");
			}
			return coreDigest(2, key, @in);
		}

		public byte[] PRF(byte[] key, byte[] address)
		{
			if (key.Length != digestSize)
			{
				throw new IllegalArgumentException("wrong key length");
			}
			if (address.Length != 32)
			{
				throw new IllegalArgumentException("wrong address length");
			}
			return coreDigest(3, key, address);
		}
	}

}