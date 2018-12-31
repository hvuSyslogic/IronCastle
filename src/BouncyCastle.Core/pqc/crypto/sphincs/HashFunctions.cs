using org.bouncycastle.crypto;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.crypto.sphincs
{

		

	public class HashFunctions
	{
		private static readonly byte[] hashc = Strings.toByteArray("expand 32-byte to 64-byte state!");

		private readonly Digest dig256;
		private readonly Digest dig512;
		private readonly Permute perm = new Permute();

		// for key pair generation where message hash not required
		public HashFunctions(Digest dig256) : this(dig256, null)
		{
		}

		public HashFunctions(Digest dig256, Digest dig512)
		{
			this.dig256 = dig256;
			this.dig512 = dig512;
		}

		public virtual int varlen_hash(byte[] @out, int outOff, byte[] @in, int inLen)
		{
			dig256.update(@in, 0, inLen);

			dig256.doFinal(@out, outOff);

			return 0;
		}

		public virtual Digest getMessageHash()
		{
			return dig512;
		}

		public virtual int hash_2n_n(byte[] @out, int outOff, byte[] @in, int inOff)
		{
			byte[] x = new byte[64];
			int i;
			for (i = 0; i < 32; i++)
			{
				x[i] = @in[inOff + i];
				x[i + 32] = hashc[i];
			}
			perm.chacha_permute(x, x);
			for (i = 0; i < 32; i++)
			{
				x[i] = (byte)(x[i] ^ @in[inOff + i + 32]);
			}
			perm.chacha_permute(x, x);
			for (i = 0; i < 32; i++)
			{
				@out[outOff + i] = x[i];
			}

			return 0;
		}

		public virtual int hash_2n_n_mask(byte[] @out, int outOff, byte[] @in, int inOff, byte[] mask, int maskOff)
		{
			byte[] buf = new byte[2 * SPHINCS256Config.HASH_BYTES];
			int i;
			for (i = 0; i < 2 * SPHINCS256Config.HASH_BYTES; i++)
			{
				buf[i] = (byte)(@in[inOff + i] ^ mask[maskOff + i]);
			}

			int rv = hash_2n_n(@out, outOff, buf, 0);

			return rv;
		}

		public virtual int hash_n_n(byte[] @out, int outOff, byte[] @in, int inOff)
		{

			byte[] x = new byte[64];
			int i;

			for (i = 0; i < 32; i++)
			{
				x[i] = @in[inOff + i];
				x[i + 32] = hashc[i];
			}
			perm.chacha_permute(x, x);
			for (i = 0; i < 32; i++)
			{
				@out[outOff + i] = x[i];
			}

			return 0;
		}

		public virtual int hash_n_n_mask(byte[] @out, int outOff, byte[] @in, int inOff, byte[] mask, int maskOff)
		{
			byte[] buf = new byte[SPHINCS256Config.HASH_BYTES];
			int i;
			for (i = 0; i < SPHINCS256Config.HASH_BYTES; i++)
			{
				buf[i] = (byte)(@in[inOff + i] ^ mask[maskOff + i]);
			}
			return hash_n_n(@out, outOff, buf, 0);
		}
	}


}