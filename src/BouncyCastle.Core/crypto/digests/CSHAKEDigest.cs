using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{
	
	/// <summary>
	/// Customizable SHAKE function.
	/// </summary>
	public class CSHAKEDigest : SHAKEDigest
	{
		private static readonly byte[] padding = new byte[100];
		private readonly byte[] diff;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="bitLength"> bit length of the underlying SHAKE function, 128 or 256. </param>
		/// <param name="N"> the function name string, note this is reserved for use by NIST. Avoid using it if not required. </param>
		/// <param name="S"> the customization string - available for local use. </param>
		public CSHAKEDigest(int bitLength, byte[] N, byte[] S) : base(bitLength)
		{

			if ((N == null || N.Length == 0) && (S == null || S.Length == 0))
			{
				diff = null;
			}
			else
			{
				diff = Arrays.concatenate(leftEncode(rate / 8), encodeString(N), encodeString(S));
				diffPadAndAbsorb();
			}
		}

		private void diffPadAndAbsorb()
		{
			int blockSize = rate / 8;
			absorb(diff, 0, diff.Length);

			int required = blockSize - (diff.Length % blockSize);

			while (required > padding.Length)
			{
				absorb(padding, 0, padding.Length);
				required -= padding.Length;
			}

			absorb(padding, 0, required);
		}

		private byte[] encodeString(byte[] str)
		{
			if (str == null || str.Length == 0)
			{
				return leftEncode(0);
			}

			return Arrays.concatenate(leftEncode(str.Length * 8L), str);
		}

		private static byte[] leftEncode(long strLen)
		{
			byte n = 1;

			long v = strLen;
			while ((v >>= 8) != 0)
			{
				n++;
			}

			byte[] b = new byte[n + 1];

			b[0] = n;

			for (int i = 1; i <= n; i++)
			{
				b[i] = (byte)(strLen >> (8 * (n - i)));
			}

			return b;
		}

		public override int doOutput(byte[] @out, int outOff, int outLen)
		{
			if (diff != null)
			{
				if (!squeezing)
				{
					absorbBits(0x00, 2);
				}

				squeeze(@out, outOff, ((long)outLen) * 8);

				return outLen;
			}
			else
			{
				return base.doOutput(@out, outOff, outLen);
			}
		}

		public override void reset()
		{
			base.reset();

			if (diff != null)
			{
				diffPadAndAbsorb();
			}
		}
	}

}