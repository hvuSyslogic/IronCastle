using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.agreement.kdf
{
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// BSI Key Derivation Function for Session Keys (see BSI-TR-03111 Section 4.3.3)
	/// </summary>
	public class GSKKFDGenerator : DigestDerivationFunction
	{
		private readonly Digest digest;

		private byte[] z;
		private int counter;
		private byte[] r;

		private byte[] buf;

		public GSKKFDGenerator(Digest digest)
		{
			this.digest = digest;
			this.buf = new byte[digest.getDigestSize()];
		}

		public virtual Digest getDigest()
		{
			return digest;
		}

		public virtual void init(DerivationParameters param)
		{
			if (param is GSKKDFParameters)
			{
				this.z = ((GSKKDFParameters)param).getZ();
				this.counter = ((GSKKDFParameters)param).getStartCounter();
				this.r = ((GSKKDFParameters)param).getNonce();
			}
			else
			{
				throw new IllegalArgumentException("unkown parameters type");
			}
		}

		public virtual int generateBytes(byte[] @out, int outOff, int len)
		{
			if (outOff + len > @out.Length)
			{
				throw new DataLengthException("output buffer too small");
			}

			digest.update(z, 0, z.Length);

			byte[] c = Pack.intToBigEndian(counter++);

			digest.update(c, 0, c.Length);

			if (r != null)
			{
				digest.update(r, 0, r.Length);
			}

			digest.doFinal(buf, 0);

			JavaSystem.arraycopy(buf, 0, @out, outOff, len);

			Arrays.clear(buf);

			return len;
		}
	}

}